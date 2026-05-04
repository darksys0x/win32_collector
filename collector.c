/*
 * win32_collector - Windows forensic artifact collector
 *
 * Single-binary triage tool. Walks 51 artifact sources (registry, WMI,
 * filesystem, raw NTFS) and dumps them as CSV. Intended for IR engagements
 * where pulling EDR-grade telemetry isn't an option.
 *
 * Build: VS2022, Release x64. Needs Administrator for raw disk access.
 *
 * See CHANGELOG.md for version history.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <lm.h>
#include <sddl.h>
#include <wincrypt.h>
#include <winnetwk.h>
#include <stdint.h>
#include <winioctl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "mpr.lib")

#define TOOL_VERSION  "2.6"

/* Globals */
static char  g_hostname[256];
static char  g_outdir[MAX_PATH];
static BOOL  g_ui = FALSE;
static BOOL  g_save = FALSE;
static BOOL  g_quick = FALSE;
static FILE *g_out = NULL;

/* Tunables. Could move to CLI flags eventually. */
static DWORD g_progress_step  = 5000;
static DWORD g_mft_max        = 500000;
static DWORD g_usn_max        = 100000;
static DWORD g_quick_limit    = 50000;


/* -- progress reporting (stderr, so it doesn't pollute --ui output) -- */

static void progress(const char *art, DWORD cur, DWORD total, const char *note)
{
    fprintf(stderr, "\r[%s] %lu", art, (unsigned long)cur);
    if (total) fprintf(stderr, "/%lu", (unsigned long)total);
    if (note)  fprintf(stderr, " %s", note);
    fprintf(stderr, "        ");
    fflush(stderr);
}

static void progress_done(const char *art, DWORD count, const char *note)
{
    fprintf(stderr, "\r[%s] done: %lu %s\n",
            art, (unsigned long)count, note ? note : "records");
    fflush(stderr);
}

static void log_err(const char *art, const char *msg, DWORD code)
{
    fprintf(stderr, "\r[%s] ERROR: %s (code=%lu)\n",
            art, msg, (unsigned long)code);
    fflush(stderr);
}


/* ---------------------------------------------------------------------------
 * NTFS structures. Not in the SDK; layouts cribbed from Russinovich/Carrier
 * and the public NTFS docs. Pack tight or things slide.
 * ------------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct {
    BYTE        Jump[3];
    BYTE        OemId[8];
    WORD        BytesPerSector;
    BYTE        SectorsPerCluster;
    WORD        ReservedSectors;
    BYTE        Unused1[3];
    WORD        Unused2;
    BYTE        MediaDescriptor;
    WORD        Unused3;
    WORD        SectorsPerTrack;
    WORD        NumberOfHeads;
    DWORD       HiddenSectors;
    DWORD       Unused4;
    DWORD       Unused5;
    LONGLONG    TotalSectors;
    LONGLONG    MftStartLcn;
    LONGLONG    Mft2StartLcn;
    signed char ClustersPerMftRecord;
    BYTE        Unused6[3];
    signed char ClustersPerIndexBlock;
    BYTE        Unused7[3];
    LONGLONG    VolumeSerialNumber;
    DWORD       Checksum;
} NTFS_BOOT_SECTOR;

typedef struct {
    DWORD       Signature;        /* 'FILE' */
    WORD        FixupOffset;
    WORD        FixupCount;
    LONGLONG    LogFileSeqNum;
    WORD        SequenceNumber;
    WORD        HardLinkCount;
    WORD        FirstAttrOffset;
    WORD        Flags;
    DWORD       UsedSize;
    DWORD       AllocatedSize;
    LONGLONG    BaseRecord;
    WORD        NextAttrId;
    WORD        Padding;
    DWORD       MftRecordNumber;
} MFT_RECORD_HEADER;

typedef struct {
    DWORD       Type;
    DWORD       Length;
    BYTE        NonResident;
    BYTE        NameLength;
    WORD        NameOffset;
    WORD        Flags;
    WORD        AttrId;
} ATTR_HEADER_COMMON;

typedef struct {
    ATTR_HEADER_COMMON Common;
    DWORD       ValueLength;
    WORD        ValueOffset;
    WORD        Flags2;
} ATTR_HEADER_RESIDENT;

typedef struct {
    ATTR_HEADER_COMMON Common;
    LONGLONG    StartingVcn;
    LONGLONG    LastVcn;
    WORD        DataRunsOffset;
    WORD        CompressionUnit;
    DWORD       Padding;
    LONGLONG    AllocatedSize;
    LONGLONG    DataSize;
    LONGLONG    InitializedSize;
} ATTR_HEADER_NONRESIDENT;

typedef struct {
    LONGLONG    CreationTime;
    LONGLONG    ModificationTime;
    LONGLONG    MftModifiedTime;
    LONGLONG    AccessTime;
    DWORD       Flags;
    DWORD       MaxVersions;
    DWORD       VersionNumber;
    DWORD       ClassId;
    DWORD       OwnerId;
    DWORD       SecurityId;
    LONGLONG    QuotaCharged;
    LONGLONG    Usn;
} STANDARD_INFORMATION;

typedef struct {
    LONGLONG    ParentRef;
    LONGLONG    CreationTime;
    LONGLONG    ModificationTime;
    LONGLONG    MftModifiedTime;
    LONGLONG    AccessTime;
    LONGLONG    AllocatedSize;
    LONGLONG    DataSize;
    DWORD       Flags;
    DWORD       ReparseValue;
    BYTE        NameLength;
    BYTE        NameType;
    WCHAR       Name[1];
} FILE_NAME_ATTR;

#pragma pack(pop)

/* attribute types */
#define ATTR_STANDARD_INFORMATION   0x10
#define ATTR_FILE_NAME              0x30
#define ATTR_DATA                   0x80
#define ATTR_END                    0xFFFFFFFF

/* MFT record flags */
#define MFT_RECORD_IN_USE           0x0001
#define MFT_RECORD_IS_DIRECTORY     0x0002

/* file attribute flags */
#define FILE_ATTR_READONLY          0x0001
#define FILE_ATTR_HIDDEN            0x0002
#define FILE_ATTR_SYSTEM            0x0004
#define FILE_ATTR_DIRECTORY         0x0010
#define FILE_ATTR_ARCHIVE           0x0020
#define FILE_ATTR_NORMAL            0x0080
#define FILE_ATTR_COMPRESSED        0x0800
#define FILE_ATTR_ENCRYPTED         0x4000
#define FILE_ATTR_SPARSE            0x0200
#define FILE_ATTR_REPARSE           0x0400
#define FILE_ATTR_NOT_INDEXED       0x2000


typedef struct {
    HANDLE      hVolume;
    DWORD       BytesPerSector;
    DWORD       SectorsPerCluster;
    DWORD       BytesPerCluster;
    DWORD       MftRecordSize;
    LONGLONG    MftStartLcn;
    BYTE       *MftBuffer;
} MFT_CONTEXT;

typedef struct {
    DWORD       RecordNumber;
    WORD        SequenceNumber;
    BOOL        InUse;
    BOOL        IsDirectory;
    LONGLONG    SI_CreationTime;
    LONGLONG    SI_ModificationTime;
    LONGLONG    SI_MftModifiedTime;
    LONGLONG    SI_AccessTime;
    DWORD       SI_Flags;
    LONGLONG    FN_CreationTime;
    LONGLONG    FN_ModificationTime;
    LONGLONG    FN_MftModifiedTime;
    LONGLONG    FN_AccessTime;
    LONGLONG    ParentRef;
    LONGLONG    FileSize;
    LONGLONG    AllocatedSize;
    WCHAR       FileName[260];
    BYTE        NameType;
    int         DataStreamCount;
    BOOL        HasADS;
} MFT_ENTRY;


/* -- helpers -- */

static void wide_to_utf8(const WCHAR *w, char *out, int outLen)
{
    if (!w) { out[0] = 0; return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outLen, NULL, NULL);
}

static void mkdir_p(const char *path)
{
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '\\') { *p = 0; CreateDirectoryA(tmp, NULL); *p = '\\'; }
    }
    CreateDirectoryA(tmp, NULL);
}

/* CSV escaping per RFC 4180 (more or less) */
static void csv_escape(char *dest, const char *src, size_t maxlen)
{
    if (!src || !src[0]) { dest[0] = 0; return; }

    int needs = 0;
    for (const char *p = src; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') { needs = 1; break; }
    }
    if (!needs) { strncpy(dest, src, maxlen - 1); dest[maxlen - 1] = 0; return; }

    size_t di = 0;
    dest[di++] = '"';
    for (const char *p = src; *p && di < maxlen - 2; p++) {
        if (*p == '"') {
            if (di < maxlen - 3) { dest[di++] = '"'; dest[di++] = '"'; }
        } else if (*p != '\r' && *p != '\n') {
            dest[di++] = *p;
        } else {
            dest[di++] = ' ';   /* flatten newlines so the CSV stays sane */
        }
    }
    dest[di++] = '"';
    dest[di]   = 0;
}

static void filetime_to_iso(FILETIME *ft, char *buf, size_t buflen)
{
    if (!ft || (ft->dwHighDateTime == 0 && ft->dwLowDateTime == 0)) { buf[0] = 0; return; }
    SYSTEMTIME st;
    FileTimeToSystemTime(ft, &st);
    snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void ntfs_time_to_iso(LONGLONG t, char *buf, size_t buflen)
{
    if (t == 0 || t == -1) { buf[0] = 0; return; }
    FILETIME ft;
    ft.dwLowDateTime  = (DWORD)(t & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(t >> 32);
    SYSTEMTIME st;
    if (FileTimeToSystemTime(&ft, &st)) {
        snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    } else {
        buf[0] = 0;
    }
}

static void md5_of_file(const char *path, char *out, size_t outlen)
{
    out[0] = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            BYTE  buf[8192];
            DWORD got;
            while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) {
                CryptHashData(hHash, buf, got, 0);
            }
            BYTE  hash[16];
            DWORD hashSize = 16;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
                for (int i = 0; i < 16 && (size_t)(i * 2 + 2) < outlen; i++)
                    sprintf(out + i * 2, "%02X", hash[i]);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(h);
}

static void process_owner(DWORD pid, char *owner, size_t len)
{
    owner[0] = 0;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return;

    HANDLE hTok;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
        DWORD size = 0;
        GetTokenInformation(hTok, TokenUser, NULL, 0, &size);
        if (size > 0) {
            TOKEN_USER *pu = (TOKEN_USER *)malloc(size);
            if (pu && GetTokenInformation(hTok, TokenUser, pu, size, &size)) {
                WCHAR name[256], domain[256];
                DWORD nLen = 256, dLen = 256;
                SID_NAME_USE snu;
                if (LookupAccountSidW(NULL, pu->User.Sid, name, &nLen, domain, &dLen, &snu)) {
                    char nameA[256], domainA[256];
                    wide_to_utf8(name,   nameA,   sizeof(nameA));
                    wide_to_utf8(domain, domainA, sizeof(domainA));
                    snprintf(owner, len, "%s\\%s", domainA, nameA);
                }
            }
            free(pu);
        }
        CloseHandle(hTok);
    }
    CloseHandle(hProc);
}

static void emit(const char *line)
{
    if (g_ui)            printf("%s\n", line);
    if (g_save && g_out) fprintf(g_out, "%s\n", line);
}

static void start_artifact(const char *name, const char *header)
{
    fprintf(stderr, "[%s] starting...\n", name);
    if (g_ui) printf("%s\n", header);

    if (g_save) {
        char dir[MAX_PATH], filepath[MAX_PATH];
        snprintf(dir, sizeof(dir), "%s\\%s", g_outdir, name);
        mkdir_p(dir);
        snprintf(filepath, sizeof(filepath), "%s\\%s.csv", dir, g_hostname);
        g_out = fopen(filepath, "w");
        if (g_out) fprintf(g_out, "%s\n", header);
    }
}

static void end_artifact(void)
{
    if (g_out) { fclose(g_out); g_out = NULL; }
}

static void attr_string(DWORD flags, char *buf, size_t buflen)
{
    (void)buflen;
    buf[0] = 0;
    if (flags & FILE_ATTR_READONLY)    strcat(buf, "R");
    if (flags & FILE_ATTR_HIDDEN)      strcat(buf, "H");
    if (flags & FILE_ATTR_SYSTEM)      strcat(buf, "S");
    if (flags & FILE_ATTR_DIRECTORY)   strcat(buf, "D");
    if (flags & FILE_ATTR_ARCHIVE)     strcat(buf, "A");
    if (flags & FILE_ATTR_COMPRESSED)  strcat(buf, "C");
    if (flags & FILE_ATTR_ENCRYPTED)   strcat(buf, "E");
    if (flags & FILE_ATTR_SPARSE)      strcat(buf, "P");
    if (flags & FILE_ATTR_REPARSE)     strcat(buf, "L");
    if (flags & FILE_ATTR_NOT_INDEXED) strcat(buf, "I");
}

static void usn_reason_string(DWORD reason, char *buf, size_t buflen)
{
    (void)buflen;
    buf[0] = 0;
    if (reason & USN_REASON_FILE_CREATE)          strcat(buf, "CREATE ");
    if (reason & USN_REASON_FILE_DELETE)          strcat(buf, "DELETE ");
    if (reason & USN_REASON_RENAME_OLD_NAME)      strcat(buf, "RENAME_OLD ");
    if (reason & USN_REASON_RENAME_NEW_NAME)      strcat(buf, "RENAME_NEW ");
    if (reason & USN_REASON_DATA_OVERWRITE)       strcat(buf, "DATA_WRITE ");
    if (reason & USN_REASON_DATA_EXTEND)          strcat(buf, "DATA_EXTEND ");
    if (reason & USN_REASON_DATA_TRUNCATION)      strcat(buf, "DATA_TRUNC ");
    if (reason & USN_REASON_SECURITY_CHANGE)      strcat(buf, "SECURITY ");
    if (reason & USN_REASON_BASIC_INFO_CHANGE)    strcat(buf, "ATTR_CHANGE ");
    if (reason & USN_REASON_HARD_LINK_CHANGE)     strcat(buf, "HARDLINK ");
    if (reason & USN_REASON_COMPRESSION_CHANGE)   strcat(buf, "COMPRESS ");
    if (reason & USN_REASON_ENCRYPTION_CHANGE)    strcat(buf, "ENCRYPT ");
    if (reason & USN_REASON_REPARSE_POINT_CHANGE) strcat(buf, "REPARSE ");
    if (reason & USN_REASON_STREAM_CHANGE)        strcat(buf, "STREAM ");
    if (reason & USN_REASON_CLOSE)                strcat(buf, "CLOSE ");

    size_t len = strlen(buf);
    if (len && buf[len - 1] == ' ') buf[len - 1] = 0;
}


/* ---------------------------------------------------------------------------
 * MFT parsing
 * ------------------------------------------------------------------------ */

/* Each MFT record has fixup values stored at sector boundaries to detect
 * torn writes. We swap them back before we trust the buffer. */
static BOOL apply_fixup(BYTE *record, DWORD recordSize, DWORD sectorSize)
{
    MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)record;
    if (hdr->Signature != 0x454C4946) return FALSE;       /* 'FILE' */

    WORD *fixup = (WORD *)(record + hdr->FixupOffset);
    WORD  sig   = fixup[0];
    WORD  count = hdr->FixupCount;

    for (WORD i = 1; i < count; i++) {
        DWORD off = (i * sectorSize) - sizeof(WORD);
        if (off + sizeof(WORD) > recordSize) break;
        WORD *end = (WORD *)(record + off);
        if (*end != sig) return FALSE;
        *end = fixup[i];
    }
    return TRUE;
}

static BOOL parse_mft_record(BYTE *record, DWORD recordSize, MFT_ENTRY *entry)
{
    memset(entry, 0, sizeof(*entry));

    MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)record;
    if (hdr->Signature != 0x454C4946) return FALSE;

    entry->RecordNumber    = hdr->MftRecordNumber;
    entry->SequenceNumber  = hdr->SequenceNumber;
    entry->InUse           = (hdr->Flags & MFT_RECORD_IN_USE) != 0;
    entry->IsDirectory     = (hdr->Flags & MFT_RECORD_IS_DIRECTORY) != 0;

    DWORD off = hdr->FirstAttrOffset;
    while (off + sizeof(ATTR_HEADER_COMMON) < recordSize) {
        ATTR_HEADER_COMMON *ah = (ATTR_HEADER_COMMON *)(record + off);
        if (ah->Type == ATTR_END || ah->Type == 0) break;
        if (ah->Length == 0 || off + ah->Length > recordSize) break;

        if (ah->NonResident == 0) {
            ATTR_HEADER_RESIDENT *res = (ATTR_HEADER_RESIDENT *)(record + off);
            BYTE *val = record + off + res->ValueOffset;

            switch (ah->Type) {
            case ATTR_STANDARD_INFORMATION:
                if (res->ValueLength >= 48) {
                    STANDARD_INFORMATION *si = (STANDARD_INFORMATION *)val;
                    entry->SI_CreationTime     = si->CreationTime;
                    entry->SI_ModificationTime = si->ModificationTime;
                    entry->SI_MftModifiedTime  = si->MftModifiedTime;
                    entry->SI_AccessTime       = si->AccessTime;
                    entry->SI_Flags            = si->Flags;
                }
                break;

            case ATTR_FILE_NAME: {
                FILE_NAME_ATTR *fn = (FILE_NAME_ATTR *)val;
                /* prefer Win32 (1) or Win32&DOS (3) names; first one wins otherwise */
                if (entry->FileName[0] == 0 || fn->NameType == 1 || fn->NameType == 3) {
                    entry->ParentRef           = fn->ParentRef & 0x0000FFFFFFFFFFFF;
                    entry->FN_CreationTime     = fn->CreationTime;
                    entry->FN_ModificationTime = fn->ModificationTime;
                    entry->FN_MftModifiedTime  = fn->MftModifiedTime;
                    entry->FN_AccessTime       = fn->AccessTime;
                    entry->FileSize            = fn->DataSize;
                    entry->AllocatedSize       = fn->AllocatedSize;
                    entry->NameType            = fn->NameType;

                    int n = fn->NameLength;
                    if (n > 259) n = 259;
                    memcpy(entry->FileName, fn->Name, n * sizeof(WCHAR));
                    entry->FileName[n] = 0;
                }
                break;
            }

            case ATTR_DATA:
                entry->DataStreamCount++;
                if (ah->NameLength > 0) entry->HasADS = TRUE;
                break;
            }
        } else {
            if (ah->Type == ATTR_DATA) {
                ATTR_HEADER_NONRESIDENT *nr = (ATTR_HEADER_NONRESIDENT *)(record + off);
                entry->DataStreamCount++;
                if (ah->NameLength > 0) entry->HasADS = TRUE;
                if (ah->NameLength == 0) {
                    entry->FileSize      = nr->DataSize;
                    entry->AllocatedSize = nr->AllocatedSize;
                }
            }
        }
        off += ah->Length;
    }
    return TRUE;
}

static BOOL mft_open(MFT_CONTEXT *ctx, const char *volume)
{
    memset(ctx, 0, sizeof(*ctx));

    /* GENERIC_READ alone is fine for MFT, but we use NO_BUFFERING so we
     * also need the buffer aligned. VirtualAlloc gives us page-aligned. */
    ctx->hVolume = CreateFileA(volume, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS,
                               NULL);
    if (ctx->hVolume == INVALID_HANDLE_VALUE) return FALSE;

    BYTE *aligned = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (!aligned) { CloseHandle(ctx->hVolume); return FALSE; }

    DWORD got;
    if (!ReadFile(ctx->hVolume, aligned, 512, &got, NULL) || got != 512) {
        VirtualFree(aligned, 0, MEM_RELEASE);
        CloseHandle(ctx->hVolume);
        return FALSE;
    }

    NTFS_BOOT_SECTOR *bs = (NTFS_BOOT_SECTOR *)aligned;
    if (memcmp(bs->OemId, "NTFS    ", 8) != 0) {
        VirtualFree(aligned, 0, MEM_RELEASE);
        CloseHandle(ctx->hVolume);
        return FALSE;
    }

    ctx->BytesPerSector    = bs->BytesPerSector;
    ctx->SectorsPerCluster = bs->SectorsPerCluster;
    ctx->BytesPerCluster   = ctx->BytesPerSector * ctx->SectorsPerCluster;
    ctx->MftStartLcn       = bs->MftStartLcn;

    /* ClustersPerMftRecord is signed: positive = clusters, negative = 2^|n| bytes */
    if (bs->ClustersPerMftRecord > 0)
        ctx->MftRecordSize = ctx->BytesPerCluster * bs->ClustersPerMftRecord;
    else
        ctx->MftRecordSize = 1u << (-bs->ClustersPerMftRecord);

    VirtualFree(aligned, 0, MEM_RELEASE);

    ctx->MftBuffer = (BYTE *)VirtualAlloc(NULL, ctx->MftRecordSize, MEM_COMMIT, PAGE_READWRITE);
    if (!ctx->MftBuffer) { CloseHandle(ctx->hVolume); return FALSE; }
    return TRUE;
}

static BOOL mft_read(MFT_CONTEXT *ctx, DWORD recno, MFT_ENTRY *entry)
{
    LONGLONG mftBase = ctx->MftStartLcn * ctx->BytesPerCluster;
    LONGLONG ofs     = mftBase + ((LONGLONG)recno * ctx->MftRecordSize);

    LARGE_INTEGER pos; pos.QuadPart = ofs;
    if (!SetFilePointerEx(ctx->hVolume, pos, NULL, FILE_BEGIN)) return FALSE;

    DWORD got;
    if (!ReadFile(ctx->hVolume, ctx->MftBuffer, ctx->MftRecordSize, &got, NULL) ||
        got != ctx->MftRecordSize) return FALSE;

    if (!apply_fixup(ctx->MftBuffer, ctx->MftRecordSize, ctx->BytesPerSector)) return FALSE;
    return parse_mft_record(ctx->MftBuffer, ctx->MftRecordSize, entry);
}

static void mft_close(MFT_CONTEXT *ctx)
{
    if (ctx->MftBuffer)                            { VirtualFree(ctx->MftBuffer, 0, MEM_RELEASE); ctx->MftBuffer = NULL; }
    if (ctx->hVolume   != INVALID_HANDLE_VALUE)    { CloseHandle(ctx->hVolume); ctx->hVolume = INVALID_HANDLE_VALUE; }
}

/*
 * Timestomping heuristic:
 *
 * On a normal Windows file, $STANDARD_INFORMATION timestamps should track
 * $FILE_NAME or be slightly *newer* (servicing, software updates etc).
 * When SI is meaningfully *older* than FN, that's the classic SetFileTime
 * footprint -- attacker dropped a new file then backdated SI to make it
 * look like it's been there forever.
 *
 * 7-day window keeps false positives down. NTFS metadata files ($MFT
 * etc.) always have weird divergent timestamps so we skip them outright.
 */
static BOOL detect_timestomp(MFT_ENTRY *e)
{
    if (e->SI_CreationTime == 0 || e->FN_CreationTime == 0) return FALSE;
    if (e->FileName[0] == L'$') return FALSE;

    LONGLONG dCreate = (e->SI_CreationTime - e->FN_CreationTime) / 10000000LL;
    if (dCreate < -604800) return TRUE;      /* SI backdated > 7d */

    LONGLONG dModify = (e->SI_ModificationTime - e->FN_ModificationTime) / 10000000LL;
    if (dModify < -604800) return TRUE;

    return FALSE;
}


/* ---------------------------------------------------------------------------
 * Collectors
 * ------------------------------------------------------------------------ */

static void Collect_MFT(void)
{
    start_artifact("MFT",
        "Endpoint,RecordNumber,SequenceNum,InUse,IsDirectory,FileName,FileSize,"
        "AllocatedSize,ParentRef,SI_Created,SI_Modified,SI_MftModified,SI_Accessed,"
        "FN_Created,FN_Modified,Attributes,HasADS,Timestomping");

    MFT_CONTEXT ctx;
    if (!mft_open(&ctx, "\\\\.\\C:")) {
        DWORD err = GetLastError();
        log_err("MFT", "open volume failed", err);
        char line[512];
        snprintf(line, sizeof(line),
                 "%s,ERROR,0,FALSE,FALSE,Failed to init MFT (err=%lu),0,0,0,,,,,,,,,",
                 g_hostname, err);
        emit(line);
        end_artifact();
        return;
    }

    DWORD maxRec = g_quick ? g_quick_limit : g_mft_max;

    /* MFT record 0 IS $MFT itself -- read it to learn the real total. */
    MFT_ENTRY e0;
    if (mft_read(&ctx, 0, &e0)) {
        if (e0.FileSize > 0 && ctx.MftRecordSize > 0) {
            DWORD total = (DWORD)(e0.FileSize / ctx.MftRecordSize);
            if (total < maxRec) maxRec = total;
            fprintf(stderr, "[MFT] total records: %lu, scanning: %lu%s\n",
                    (unsigned long)total, (unsigned long)maxRec,
                    g_quick ? " (quick mode)" : "");
        }
    }

    DWORD scanned = 0, output = 0, errors = 0;
    DWORD t0 = GetTickCount();

    for (DWORD i = 0; i < maxRec; i++) {
        MFT_ENTRY e;
        if (!mft_read(&ctx, i, &e)) {
            errors++;
            if (errors > 100 && scanned < 10) {
                log_err("MFT", "too many read errors, aborting", errors);
                break;
            }
            continue;
        }
        scanned++;

        if (e.FileName[0] == 0) continue;

        char siC[32], siM[32], siMM[32], siA[32], fnC[32], fnM[32];
        ntfs_time_to_iso(e.SI_CreationTime,     siC,  sizeof(siC));
        ntfs_time_to_iso(e.SI_ModificationTime, siM,  sizeof(siM));
        ntfs_time_to_iso(e.SI_MftModifiedTime,  siMM, sizeof(siMM));
        ntfs_time_to_iso(e.SI_AccessTime,       siA,  sizeof(siA));
        ntfs_time_to_iso(e.FN_CreationTime,     fnC,  sizeof(fnC));
        ntfs_time_to_iso(e.FN_ModificationTime, fnM,  sizeof(fnM));

        char attrs[32];
        attr_string(e.SI_Flags, attrs, sizeof(attrs));
        BOOL stomped = detect_timestomp(&e);

        char fname[520], fnameEsc[1040];
        wide_to_utf8(e.FileName, fname, sizeof(fname));
        csv_escape(fnameEsc, fname, sizeof(fnameEsc));

        char line[4096];
        snprintf(line, sizeof(line),
                 "%s,%lu,%u,%s,%s,%s,%lld,%lld,%lld,%s,%s,%s,%s,%s,%s,%s,%s,%s",
                 g_hostname, (unsigned long)e.RecordNumber, e.SequenceNumber,
                 e.InUse ? "TRUE" : "FALSE", e.IsDirectory ? "TRUE" : "FALSE",
                 fnameEsc, e.FileSize, e.AllocatedSize, e.ParentRef,
                 siC, siM, siMM, siA, fnC, fnM,
                 attrs, e.HasADS ? "TRUE" : "FALSE",
                 stomped ? "SUSPICIOUS" : "");
        emit(line);
        output++;

        if (scanned % g_progress_step == 0) {
            DWORD elapsed = (GetTickCount() - t0) / 1000;
            DWORD rate = elapsed ? scanned / elapsed : 0;
            progress("MFT", scanned, maxRec, rate ? "rec/s" : "");
        }
    }

    progress_done("MFT", output, "records output");
    mft_close(&ctx);
    end_artifact();
}

static void Collect_UsnJrnlFull(void)
{
    start_artifact("UsnJrnl_Full",
        "Endpoint,USN,Timestamp,FileName,FileRef,ParentRef,Reason,ReasonFlags,FileAttributes");

    HANDLE hVol = CreateFileA("\\\\.\\C:", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_err("UsnJrnl", "open volume failed", err);
        char line[512];
        snprintf(line, sizeof(line), "%s,ERROR,,,,,Failed to open volume (err=%lu),,",
                 g_hostname, err);
        emit(line);
        end_artifact();
        return;
    }

    USN_JOURNAL_DATA jd;
    DWORD bytes;
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0,
                         &jd, sizeof(jd), &bytes, NULL)) {
        DWORD err = GetLastError();
        log_err("UsnJrnl", "journal query failed", err);
        char line[512];
        snprintf(line, sizeof(line), "%s,ERROR,,,,,USN Journal query failed (err=%lu),,",
                 g_hostname, err);
        emit(line);
        CloseHandle(hVol);
        end_artifact();
        return;
    }

    fprintf(stderr, "[UsnJrnl] journal id: 0x%llX, first usn: %lld\n",
            (unsigned long long)jd.UsnJournalID, (long long)jd.FirstUsn);

    READ_USN_JOURNAL_DATA rd;
    memset(&rd, 0, sizeof(rd));
    rd.StartUsn          = jd.FirstUsn;
    rd.ReasonMask        = 0xFFFFFFFF;
    rd.ReturnOnlyOnClose = FALSE;
    rd.Timeout           = 0;
    rd.BytesToWaitFor    = 0;
    rd.UsnJournalID      = jd.UsnJournalID;

    BYTE  buf[65536];
    DWORD output = 0;
    DWORD maxRec = g_quick ? g_quick_limit : g_usn_max;

    while (output < maxRec) {
        if (!DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &rd, sizeof(rd),
                             buf, sizeof(buf), &bytes, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_HANDLE_EOF && output == 0)
                log_err("UsnJrnl", "read failed", err);
            break;
        }
        if (bytes <= sizeof(USN)) break;

        rd.StartUsn = *(USN *)buf;

        BYTE *p   = buf + sizeof(USN);
        BYTE *end = buf + bytes;

        while (p < end && output < maxRec) {
            PUSN_RECORD r = (PUSN_RECORD)p;
            if (r->RecordLength == 0)              break;
            if (p + r->RecordLength > end)         break;

            WCHAR name[260];
            int n = r->FileNameLength / sizeof(WCHAR);
            if (n > 259) n = 259;
            memcpy(name, (BYTE *)r + r->FileNameOffset, n * sizeof(WCHAR));
            name[n] = 0;

            char nameA[520];
            wide_to_utf8(name, nameA, sizeof(nameA));

            char ts[32];
            FILETIME ft;
            ft.dwLowDateTime  = r->TimeStamp.LowPart;
            ft.dwHighDateTime = r->TimeStamp.HighPart;
            filetime_to_iso(&ft, ts, sizeof(ts));

            char reasonStr[256];
            usn_reason_string(r->Reason, reasonStr, sizeof(reasonStr));

            char attrs[32];
            attr_string(r->FileAttributes, attrs, sizeof(attrs));

            char nameEsc[1040];
            csv_escape(nameEsc, nameA, sizeof(nameEsc));

            char line[2048];
            snprintf(line, sizeof(line),
                     "%s,%lld,%s,%s,%lld,%lld,0x%08X,%s,%s",
                     g_hostname, (long long)r->Usn, ts, nameEsc,
                     (long long)(r->FileReferenceNumber       & 0x0000FFFFFFFFFFFF),
                     (long long)(r->ParentFileReferenceNumber & 0x0000FFFFFFFFFFFF),
                     r->Reason, reasonStr, attrs);
            emit(line);
            output++;
            p += r->RecordLength;
        }

        if (output % g_progress_step == 0)
            progress("UsnJrnl", output, maxRec, "records");
    }

    progress_done("UsnJrnl", output, "records");
    CloseHandle(hVol);
    end_artifact();
}

/* TODO: $LogFile parsing is shallow -- only checks restart areas and
 * counts RCRD pages. Full transaction parsing would need a proper LSN
 * walker. For triage that's usually enough to flag dirty/intact. */
static void Collect_LogFile(void)
{
    start_artifact("LogFile", "Endpoint,Offset,LSN,RecordType,Status,Details");

    HANDLE hVol = CreateFileA("\\\\.\\C:", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING,
                              FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_err("LogFile", "open volume failed", err);
        char line[512];
        snprintf(line, sizeof(line),
                 "%s,ERROR,0,ERROR,FAILED,Failed to open volume (err=%lu)",
                 g_hostname, err);
        emit(line);
        end_artifact();
        return;
    }

    BYTE *aligned = (BYTE *)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (!aligned) { CloseHandle(hVol); end_artifact(); return; }

    DWORD got;
    if (!ReadFile(hVol, aligned, 512, &got, NULL) || got != 512) {
        log_err("LogFile", "boot sector read failed", GetLastError());
        VirtualFree(aligned, 0, MEM_RELEASE);
        CloseHandle(hVol);
        end_artifact();
        return;
    }

    NTFS_BOOT_SECTOR *bs = (NTFS_BOOT_SECTOR *)aligned;
    if (memcmp(bs->OemId, "NTFS    ", 8) != 0) {
        log_err("LogFile", "not NTFS volume", 0);
        VirtualFree(aligned, 0, MEM_RELEASE);
        CloseHandle(hVol);
        end_artifact();
        return;
    }

    DWORD bpc = bs->BytesPerSector * bs->SectorsPerCluster;
    DWORD mftRecSize = (bs->ClustersPerMftRecord > 0)
                        ? bpc * bs->ClustersPerMftRecord
                        : (1u << (-bs->ClustersPerMftRecord));

    /* $LogFile is MFT entry 2 */
    LONGLONG logRecOff = (bs->MftStartLcn * bpc) + (2LL * mftRecSize);
    VirtualFree(aligned, 0, MEM_RELEASE);

    BYTE *rec = (BYTE *)VirtualAlloc(NULL, mftRecSize, MEM_COMMIT, PAGE_READWRITE);
    if (!rec) { CloseHandle(hVol); end_artifact(); return; }

    LARGE_INTEGER pos; pos.QuadPart = logRecOff;
    SetFilePointerEx(hVol, pos, NULL, FILE_BEGIN);

    if (!ReadFile(hVol, rec, mftRecSize, &got, NULL) || got != mftRecSize) {
        log_err("LogFile", "MFT record read failed", GetLastError());
        VirtualFree(rec, 0, MEM_RELEASE);
        CloseHandle(hVol);
        end_artifact();
        return;
    }

    MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)rec;
    if (hdr->Signature != 0x454C4946) {
        log_err("LogFile", "invalid MFT signature", hdr->Signature);
        VirtualFree(rec, 0, MEM_RELEASE);
        CloseHandle(hVol);
        end_artifact();
        return;
    }

    /* fixup */
    WORD *fa = (WORD *)(rec + hdr->FixupOffset);
    for (WORD i = 1; i < hdr->FixupCount && i <= mftRecSize / 512; i++) {
        DWORD off = (i * 512) - sizeof(WORD);
        if (off < mftRecSize) *(WORD *)(rec + off) = fa[i];
    }

    /* find first DATA attribute, then walk the run list to its first LCN */
    DWORD off = hdr->FirstAttrOffset;
    LONGLONG logSize = 0;
    LONGLONG logLcn  = 0;

    while (off + 24 < mftRecSize) {
        ATTR_HEADER_COMMON *ah = (ATTR_HEADER_COMMON *)(rec + off);
        if (ah->Type == 0xFFFFFFFF || ah->Type == 0) break;
        if (ah->Length == 0) break;

        if (ah->Type == 0x80 && ah->NonResident) {
            ATTR_HEADER_NONRESIDENT *nr = (ATTR_HEADER_NONRESIDENT *)(rec + off);
            logSize = nr->DataSize;

            BYTE *runs = rec + off + nr->DataRunsOffset;
            if (runs[0]) {
                int lenBytes = runs[0] & 0x0F;
                int offBytes = (runs[0] >> 4) & 0x0F;
                if (lenBytes > 0 && offBytes > 0) {
                    LONGLONG lcn = 0;
                    for (int i = 0; i < offBytes; i++)
                        lcn |= ((LONGLONG)runs[1 + lenBytes + i]) << (8 * i);
                    /* sign extend */
                    if (offBytes > 0 && (runs[1 + lenBytes + offBytes - 1] & 0x80)) {
                        for (int i = offBytes; i < 8; i++)
                            lcn |= (0xFFLL << (8 * i));
                    }
                    logLcn = lcn;
                }
            }
            break;
        }
        off += ah->Length;
    }

    VirtualFree(rec, 0, MEM_RELEASE);

    if (logLcn > 0) {
        pos.QuadPart = logLcn * bpc;
        SetFilePointerEx(hVol, pos, NULL, FILE_BEGIN);

        BYTE *logBuf = (BYTE *)VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
        if (logBuf) {
            if (ReadFile(hVol, logBuf, 65536, &got, NULL) && got >= 4096) {
                char line[512];
                if (memcmp(logBuf, "RSTR", 4) == 0) {
                    snprintf(line, sizeof(line),
                             "%s,0,0,RESTART_PAGE,VALID,$LogFile restart area - journal intact",
                             g_hostname);
                    emit(line);
                    LONGLONG lsn = *(LONGLONG *)(logBuf + 8);
                    snprintf(line, sizeof(line), "%s,8,%lld,CURRENT_LSN,VALID,Current LSN",
                             g_hostname, lsn);
                    emit(line);
                } else if (memcmp(logBuf, "CHKD", 4) == 0) {
                    snprintf(line, sizeof(line),
                             "%s,0,0,CHECKPOINT,DIRTY,Unclean shutdown detected",
                             g_hostname);
                    emit(line);
                } else {
                    snprintf(line, sizeof(line),
                             "%s,0,0,UNKNOWN,0x%02X%02X%02X%02X,Unknown signature",
                             g_hostname, logBuf[0], logBuf[1], logBuf[2], logBuf[3]);
                    emit(line);
                }

                if (got >= 0x1000 + 4 && memcmp(logBuf + 0x1000, "RSTR", 4) == 0) {
                    snprintf(line, sizeof(line),
                             "%s,4096,0,RESTART_PAGE_2,VALID,Second restart area intact",
                             g_hostname);
                    emit(line);
                }

                int rcrd = 0;
                for (DWORD i = 0x2000; i < got - 4 && rcrd < 100; i += 0x1000) {
                    if (memcmp(logBuf + i, "RCRD", 4) == 0) rcrd++;
                }
                if (rcrd > 0) {
                    snprintf(line, sizeof(line),
                             "%s,8192,0,RECORD_PAGES,%d,%d transaction pages found",
                             g_hostname, rcrd, rcrd);
                    emit(line);
                }
            }
            VirtualFree(logBuf, 0, MEM_RELEASE);
        }
    }

    char summary[512];
    snprintf(summary, sizeof(summary),
             "%s,SUMMARY,0,LOGFILE_SIZE,%lld,Use LogFileParser for detailed analysis",
             g_hostname, logSize);
    emit(summary);

    progress_done("LogFile", 1, "analyzed");
    CloseHandle(hVol);
    end_artifact();
}


/* -- process / module enumeration -- */

static void Collect_ProcessList(void)
{
    start_artifact("ProcessList",
        "Endpoint,PID,PPID,Name,ExecutablePath,Owner,ThreadCount,HandleCount,WorkingSetSize,CreateTime");

    DWORD count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                char path[MAX_PATH] = "", owner[256] = "", ts[64] = "", exeName[260] = "";
                DWORD handles = 0;
                SIZE_T mem    = 0;
                wide_to_utf8(pe.szExeFile, exeName, sizeof(exeName));

                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                           FALSE, pe.th32ProcessID);
                if (hProc) {
                    WCHAR wpath[MAX_PATH]; DWORD len = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProc, 0, wpath, &len))
                        wide_to_utf8(wpath, path, sizeof(path));

                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                        mem = pmc.WorkingSetSize;

                    GetProcessHandleCount(hProc, &handles);

                    FILETIME c, e, k, u;
                    if (GetProcessTimes(hProc, &c, &e, &k, &u))
                        filetime_to_iso(&c, ts, sizeof(ts));

                    CloseHandle(hProc);
                }
                process_owner(pe.th32ProcessID, owner, sizeof(owner));

                char escPath[MAX_PATH * 2], escOwner[512];
                csv_escape(escPath,  path,  sizeof(escPath));
                csv_escape(escOwner, owner, sizeof(escOwner));

                char line[4096];
                snprintf(line, sizeof(line),
                         "%s,%lu,%lu,%s,%s,%s,%lu,%lu,%zu,%s",
                         g_hostname,
                         (unsigned long)pe.th32ProcessID,
                         (unsigned long)pe.th32ParentProcessID,
                         exeName, escPath, escOwner,
                         (unsigned long)pe.cntThreads,
                         (unsigned long)handles, mem, ts);
                emit(line);
                count++;
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    progress_done("ProcessList", count, "processes");
    end_artifact();
}

static void Collect_LoadedDLLs(void)
{
    start_artifact("LoadedDLLs",
        "Endpoint,PID,ProcessName,DLLName,DLLPath,BaseAddress,Size");

    DWORD count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                char exeName[260];
                wide_to_utf8(pe.szExeFile, exeName, sizeof(exeName));

                HANDLE hMod = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
                if (hMod != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me; me.dwSize = sizeof(me);
                    if (Module32FirstW(hMod, &me)) {
                        do {
                            char modName[260], modPath[MAX_PATH];
                            wide_to_utf8(me.szModule,  modName, sizeof(modName));
                            wide_to_utf8(me.szExePath, modPath, sizeof(modPath));

                            char escPath[MAX_PATH * 2];
                            csv_escape(escPath, modPath, sizeof(escPath));

                            char line[2048];
                            snprintf(line, sizeof(line),
                                     "%s,%lu,%s,%s,%s,0x%p,%lu",
                                     g_hostname, (unsigned long)pe.th32ProcessID,
                                     exeName, modName, escPath,
                                     (void *)me.modBaseAddr,
                                     (unsigned long)me.modBaseSize);
                            emit(line);
                            count++;
                        } while (Module32NextW(hMod, &me));
                    }
                    CloseHandle(hMod);
                }
                if (count && count % 5000 == 0)
                    progress("LoadedDLLs", count, 0, "DLLs");
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    progress_done("LoadedDLLs", count, "DLLs");
    end_artifact();
}

static void Collect_DLLs_NoPath(void)
{
    start_artifact("DLLs_NoPath",
        "Endpoint,PID,ProcessName,DLLName,DLLPath,Suspicious_Reason");

    DWORD count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                char exeName[260];
                wide_to_utf8(pe.szExeFile, exeName, sizeof(exeName));

                HANDLE hMod = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
                if (hMod != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32W me; me.dwSize = sizeof(me);
                    if (Module32FirstW(hMod, &me)) {
                        do {
                            char modName[260], modPath[MAX_PATH];
                            wide_to_utf8(me.szModule,  modName, sizeof(modName));
                            wide_to_utf8(me.szExePath, modPath, sizeof(modPath));

                            int sus = 0;
                            char reason[128] = "";
                            if      (!strchr(modPath, '\\'))                { sus = 1; strcpy(reason, "No path");        }
                            else if (strstr(modPath, "\\Temp\\"))            { sus = 1; strcpy(reason, "Temp folder");    }
                            else if (strstr(modPath, "\\Users\\Public\\"))   { sus = 1; strcpy(reason, "Public folder");  }
                            else if (strstr(modPath, "\\Downloads\\"))       { sus = 1; strcpy(reason, "Downloads");      }

                            if (sus) {
                                char escPath[MAX_PATH * 2];
                                csv_escape(escPath, modPath, sizeof(escPath));
                                char line[2048];
                                snprintf(line, sizeof(line),
                                         "%s,%lu,%s,%s,%s,%s",
                                         g_hostname, (unsigned long)pe.th32ProcessID,
                                         exeName, modName, escPath, reason);
                                emit(line);
                                count++;
                            }
                        } while (Module32NextW(hMod, &me));
                    }
                    CloseHandle(hMod);
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    progress_done("DLLs_NoPath", count, "suspicious");
    end_artifact();
}

static void Collect_Drivers(void)
{
    start_artifact("Drivers", "Endpoint,Name,DisplayName,State,StartType,BinaryPath");

    DWORD count = 0;
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) { progress_done("Drivers", 0, "drivers"); end_artifact(); return; }

    DWORD needed = 0, returned = 0, resume = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL,
                          NULL, 0, &needed, &returned, &resume, NULL);

    if (needed > 0) {
        BYTE *buf = (BYTE *)malloc(needed);
        if (buf && EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                         SERVICE_STATE_ALL, buf, needed, &needed,
                                         &returned, &resume, NULL)) {
            ENUM_SERVICE_STATUS_PROCESSA *svc = (ENUM_SERVICE_STATUS_PROCESSA *)buf;
            for (DWORD i = 0; i < returned; i++) {
                SC_HANDLE hS = OpenServiceA(hSCM, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (!hS) continue;

                DWORD n = 0; QueryServiceConfigA(hS, NULL, 0, &n);
                if (n > 0) {
                    QUERY_SERVICE_CONFIGA *cfg = (QUERY_SERVICE_CONFIGA *)malloc(n);
                    if (cfg && QueryServiceConfigA(hS, cfg, n, &n)) {
                        const char *state = svc[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING
                                            ? "Running" : "Stopped";
                        const char *start = "Other";
                        switch (cfg->dwStartType) {
                        case SERVICE_BOOT_START:   start = "Boot";     break;
                        case SERVICE_SYSTEM_START: start = "System";   break;
                        case SERVICE_AUTO_START:   start = "Auto";     break;
                        case SERVICE_DEMAND_START: start = "Manual";   break;
                        case SERVICE_DISABLED:     start = "Disabled"; break;
                        }
                        char escPath[MAX_PATH * 2], escDisp[512];
                        csv_escape(escPath, cfg->lpBinaryPathName,  sizeof(escPath));
                        csv_escape(escDisp, svc[i].lpDisplayName,   sizeof(escDisp));
                        char line[4096];
                        snprintf(line, sizeof(line), "%s,%s,%s,%s,%s,%s",
                                 g_hostname, svc[i].lpServiceName, escDisp,
                                 state, start, escPath);
                        emit(line);
                        count++;
                    }
                    free(cfg);
                }
                CloseServiceHandle(hS);
            }
        }
        free(buf);
    }
    CloseServiceHandle(hSCM);

    progress_done("Drivers", count, "drivers");
    end_artifact();
}


/* -- persistence -- */

static void Collect_Services(void)
{
    start_artifact("Services",
        "Endpoint,Name,DisplayName,State,StartType,BinaryPath,StartName,PID");

    DWORD count = 0;
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) { progress_done("Services", 0, "services"); end_artifact(); return; }

    DWORD needed = 0, returned = 0, resume = 0;
    EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &needed, &returned, &resume, NULL);
    if (needed > 0) {
        BYTE *buf = (BYTE *)malloc(needed);
        if (buf && EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                         SERVICE_STATE_ALL, buf, needed, &needed,
                                         &returned, &resume, NULL)) {
            ENUM_SERVICE_STATUS_PROCESSA *svc = (ENUM_SERVICE_STATUS_PROCESSA *)buf;
            for (DWORD i = 0; i < returned; i++) {
                SC_HANDLE hS = OpenServiceA(hSCM, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
                if (!hS) continue;
                DWORD n = 0; QueryServiceConfigA(hS, NULL, 0, &n);
                if (n > 0) {
                    QUERY_SERVICE_CONFIGA *cfg = (QUERY_SERVICE_CONFIGA *)malloc(n);
                    if (cfg && QueryServiceConfigA(hS, cfg, n, &n)) {
                        const char *state = "Other";
                        switch (svc[i].ServiceStatusProcess.dwCurrentState) {
                        case SERVICE_RUNNING: state = "Running"; break;
                        case SERVICE_STOPPED: state = "Stopped"; break;
                        case SERVICE_PAUSED:  state = "Paused";  break;
                        }
                        const char *start = "Other";
                        switch (cfg->dwStartType) {
                        case SERVICE_AUTO_START:   start = "Auto";     break;
                        case SERVICE_DEMAND_START: start = "Manual";   break;
                        case SERVICE_DISABLED:     start = "Disabled"; break;
                        }
                        char escPath[MAX_PATH * 2], escDisp[512], escStart[256];
                        csv_escape(escPath,  cfg->lpBinaryPathName,    sizeof(escPath));
                        csv_escape(escDisp,  svc[i].lpDisplayName,     sizeof(escDisp));
                        csv_escape(escStart, cfg->lpServiceStartName,  sizeof(escStart));
                        char line[4096];
                        snprintf(line, sizeof(line),
                                 "%s,%s,%s,%s,%s,%s,%s,%lu",
                                 g_hostname, svc[i].lpServiceName, escDisp, state, start,
                                 escPath, escStart,
                                 (unsigned long)svc[i].ServiceStatusProcess.dwProcessId);
                        emit(line);
                        count++;
                    }
                    free(cfg);
                }
                CloseServiceHandle(hS);
            }
        }
        free(buf);
    }
    CloseServiceHandle(hSCM);

    progress_done("Services", count, "services");
    end_artifact();
}

/* schtasks parsing is fragile; locale-dependent. CSV format is the least bad option. */
static void Collect_ScheduledTasks(void)
{
    start_artifact("Scheduled_Tasks",
        "Endpoint,TaskName,Status,NextRunTime,LastRunTime,Author,TaskToRun");

    DWORD count = 0;
    FILE *pipe = _popen("schtasks /query /fo csv /v 2>nul", "r");
    if (pipe) {
        char line[8192];
        int  lineNum = 0;
        while (fgets(line, sizeof(line), pipe)) {
            lineNum++;
            if (lineNum == 1) continue;          /* skip header */
            char *nl = strchr(line, '\n'); if (nl) *nl = 0;
            if (strlen(line) > 10) {
                char out[8300];
                snprintf(out, sizeof(out), "%s,%s", g_hostname, line);
                emit(out);
                count++;
            }
            if (count && count % 100 == 0) progress("Scheduled_Tasks", count, 0, "tasks");
        }
        _pclose(pipe);
    }
    progress_done("Scheduled_Tasks", count, "tasks");
    end_artifact();
}

static void Collect_Autoruns(void)
{
    start_artifact("Autoruns", "Endpoint,Location,Name,Value,ValueType");

    /* common Run/RunOnce keys -- not exhaustive, but covers >90% of crap */
    struct {
        HKEY        hive;
        const char *key;
        const char *name;
    } locs[] = {
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",                              "HKLM\\Run"      },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",                          "HKLM\\RunOnce"  },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",                 "HKLM\\Run32"    },
        { HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",                              "HKCU\\Run"      },
        { HKEY_CURRENT_USER,  "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",                          "HKCU\\RunOnce"  },
    };

    DWORD count = 0;
    for (int i = 0; i < (int)(sizeof(locs)/sizeof(locs[0])); i++) {
        HKEY hKey;
        if (RegOpenKeyExA(locs[i].hive, locs[i].key, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        DWORD idx = 0;
        char  valName[256];
        DWORD valLen;
        BYTE  data[4096];
        DWORD dataLen, type;

        for (;;) {
            valLen  = sizeof(valName);
            dataLen = sizeof(data);
            if (RegEnumValueA(hKey, idx++, valName, &valLen, NULL, &type, data, &dataLen)
                != ERROR_SUCCESS) break;

            char escVal[8192];
            const char *typeStr = "Binary";
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                csv_escape(escVal, (char *)data, sizeof(escVal));
                typeStr = (type == REG_SZ) ? "REG_SZ" : "REG_EXPAND_SZ";
            } else if (type == REG_DWORD) {
                snprintf(escVal, sizeof(escVal), "%lu", *(DWORD *)data);
                typeStr = "REG_DWORD";
            } else {
                snprintf(escVal, sizeof(escVal), "(binary %lu bytes)", (unsigned long)dataLen);
            }
            char line[8500];
            snprintf(line, sizeof(line), "%s,%s,%s,%s,%s",
                     g_hostname, locs[i].name, valName, escVal, typeStr);
            emit(line);
            count++;
        }
        RegCloseKey(hKey);
    }
    progress_done("Autoruns", count, "entries");
    end_artifact();
}

static void Collect_WMIPersistence(void)
{
    start_artifact("WMIPer", "Endpoint,Type,Name,Details");

    DWORD count = 0;
    /* TODO: switch to direct COM via IWbemServices instead of shelling out */
    FILE *pipe = _popen("wmic /namespace:\\\\root\\subscription path "
                        "CommandLineEventConsumer get Name,CommandLineTemplate "
                        "/format:csv 2>nul", "r");
    if (pipe) {
        char line[4096];
        while (fgets(line, sizeof(line), pipe)) {
            if (strlen(line) > 10 && !strstr(line, "Node,") && !strstr(line, "No Instance")) {
                char *nl = strchr(line, '\n'); if (nl) *nl = 0;
                char out[4200];
                snprintf(out, sizeof(out), "%s,CommandLineEventConsumer,,%s", g_hostname, line);
                emit(out);
                count++;
            }
        }
        _pclose(pipe);
    }
    progress_done("WMIPer", count, "consumers");
    end_artifact();
}

/* Sticky-keys / accessibility-tools backdoor check (sethc.exe et al) */
static void Collect_StickyKey(void)
{
    start_artifact("StickyKey_Detector",
        "Endpoint,File,Exists,Size,LastWriteTime,MD5,IFEO_Debugger");

    static const char *tools[] = {
        "sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe"
    };

    for (int i = 0; i < 5; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "C:\\Windows\\System32\\%s", tools[i]);

        char debugger[512] = "";
        char keyPath[256];
        snprintf(keyPath, sizeof(keyPath),
                 "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                 "Image File Execution Options\\%s", tools[i]);

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD sz = sizeof(debugger);
            RegQueryValueExA(hKey, "Debugger", NULL, NULL, (BYTE *)debugger, &sz);
            RegCloseKey(hKey);
        }

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(path, &fd);
        char line[1024];
        if (hFind != INVALID_HANDLE_VALUE) {
            char ts[64], hash[64] = "";
            filetime_to_iso(&fd.ftLastWriteTime, ts, sizeof(ts));
            md5_of_file(path, hash, sizeof(hash));
            snprintf(line, sizeof(line), "%s,%s,TRUE,%lu,%s,%s,%s",
                     g_hostname, tools[i], (unsigned long)fd.nFileSizeLow, ts, hash, debugger);
            FindClose(hFind);
        } else {
            snprintf(line, sizeof(line), "%s,%s,FALSE,0,,,%s",
                     g_hostname, tools[i], debugger);
        }
        emit(line);
    }
    progress_done("StickyKey", 5, "files checked");
    end_artifact();
}

static void Collect_IFEO(void)
{
    start_artifact("IFEO", "Endpoint,ImageName,Debugger,GlobalFlag");

    DWORD count = 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                      "Image File Execution Options",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char  subkey[256];
        DWORD len;
        for (;;) {
            len = sizeof(subkey);
            if (RegEnumKeyExA(hKey, idx++, subkey, &len, NULL, NULL, NULL, NULL)
                != ERROR_SUCCESS) break;
            HKEY hSub;
            if (RegOpenKeyExA(hKey, subkey, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                char  debugger[512] = "";
                DWORD globalFlag    = 0;
                DWORD sz;

                sz = sizeof(debugger);
                RegQueryValueExA(hSub, "Debugger",   NULL, NULL, (BYTE *)debugger,    &sz);

                sz = sizeof(globalFlag);
                RegQueryValueExA(hSub, "GlobalFlag", NULL, NULL, (BYTE *)&globalFlag, &sz);

                if (debugger[0] || globalFlag != 0) {
                    char escDbg[600];
                    csv_escape(escDbg, debugger, sizeof(escDbg));
                    char line[1024];
                    snprintf(line, sizeof(line), "%s,%s,%s,%lu",
                             g_hostname, subkey, escDbg, (unsigned long)globalFlag);
                    emit(line);
                    count++;
                }
                RegCloseKey(hSub);
            }
        }
        RegCloseKey(hKey);
    }
    progress_done("IFEO", count, "hijacks found");
    end_artifact();
}

static void Collect_BITSJobs(void)
{
    start_artifact("BITSJobs",
        "Endpoint,JobName,Owner,State,Type,URL,LocalFile");

    DWORD count = 0;
    FILE *pipe = _popen("bitsadmin /list /allusers /verbose 2>nul", "r");
    if (pipe) {
        char line[4096];
        char jobName[256] = "", owner[256] = "", state[64] = "";
        while (fgets(line, sizeof(line), pipe)) {
            char *nl = strchr(line, '\n'); if (nl) *nl = 0;

            if (strstr(line, "DISPLAY NAME:")) {
                char *v = strchr(line, ':');
                if (v) { v += 2; strncpy(jobName, v, sizeof(jobName) - 1); }
            } else if (strstr(line, "OWNER:")) {
                char *v = strchr(line, ':');
                if (v) { v += 2; strncpy(owner, v, sizeof(owner) - 1); }
            } else if (strstr(line, "STATE:")) {
                char *v = strchr(line, ':');
                if (v) { v += 2; strncpy(state, v, sizeof(state) - 1); }
            } else if (strstr(line, "LOCAL NAME:") && jobName[0]) {
                char out[4096];
                snprintf(out, sizeof(out), "%s,%s,%s,%s,,,",
                         g_hostname, jobName, owner, state);
                emit(out);
                count++;
                jobName[0] = owner[0] = state[0] = 0;
            }
        }
        _pclose(pipe);
    }
    progress_done("BITSJobs", count, "jobs");
    end_artifact();
}


/* -- execution evidence -- */

static void Collect_Prefetch(void)
{
    start_artifact("Prefetch",
        "Endpoint,FileName,ExecutableName,LastRunTime,CreationTime,FileHash,FileSize");

    DWORD count = 0;
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\Prefetch\\*.pf", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "C:\\Windows\\Prefetch\\%s", fd.cFileName);

            char lastRun[64], created[64], hash[64];
            filetime_to_iso(&fd.ftLastWriteTime, lastRun, sizeof(lastRun));
            filetime_to_iso(&fd.ftCreationTime,  created, sizeof(created));
            md5_of_file(path, hash, sizeof(hash));

            char exeName[256];
            strncpy(exeName, fd.cFileName, sizeof(exeName) - 1);
            char *dash = strrchr(exeName, '-');
            if (dash) *dash = 0;

            char line[1024];
            snprintf(line, sizeof(line),
                     "%s,%s,%s,%s,%s,%s,%lu",
                     g_hostname, fd.cFileName, exeName, lastRun, created, hash,
                     (unsigned long)fd.nFileSizeLow);
            emit(line);
            count++;
            if (count % 100 == 0) progress("Prefetch", count, 0, "files");
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    progress_done("Prefetch", count, "files");
    end_artifact();
}

/* ShimCache lives in the registry but the binary blob format is non-trivial.
 * We just point at it for offline parsing. */
static void Collect_ShimCache(void)
{
    start_artifact("ShimCache", "Endpoint,RegistryPath,DataSize,Note");

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dataSize = 0;
        RegQueryValueExA(hKey, "AppCompatCache", NULL, NULL, NULL, &dataSize);
        char line[512];
        snprintf(line, sizeof(line),
                 "%s,HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache,"
                 "%lu,Parse with ShimCacheParser",
                 g_hostname, (unsigned long)dataSize);
        emit(line);
        RegCloseKey(hKey);
    }
    progress_done("ShimCache", 1, "registry key");
    end_artifact();
}

static void Collect_Amcache(void)
{
    start_artifact("Amcache",
        "Endpoint,FullPath,FileName,Size,CreationTime,LastWriteTime");

    DWORD count = 0;
    static const char *paths[] = {
        "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
        "C:\\Windows\\AppCompat\\Programs\\RecentFileCache.bcf"
    };
    for (int i = 0; i < 2; i++) {
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(paths[i], &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            char cTime[64], wTime[64];
            filetime_to_iso(&fd.ftCreationTime,  cTime, sizeof(cTime));
            filetime_to_iso(&fd.ftLastWriteTime, wTime, sizeof(wTime));
            char line[1024];
            snprintf(line, sizeof(line), "%s,%s,%s,%lu,%s,%s",
                     g_hostname, paths[i], fd.cFileName,
                     (unsigned long)fd.nFileSizeLow, cTime, wTime);
            emit(line);
            count++;
            FindClose(hFind);
        }
    }
    progress_done("Amcache", count, "files");
    end_artifact();
}

static void Collect_UserAssist(void)
{
    start_artifact("UserAssist", "Endpoint,User,GUID,ValueName,Note");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if ((ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                && strcmp(ud.cFileName, ".") && strcmp(ud.cFileName, "..")) {
                char line[1024];
                snprintf(line, sizeof(line),
                         "%s,%s,CEBFF5CD-ACE2-4F4F-9178-9926F41749EA,,"
                         "ROT13 encoded - parse with UserAssist tools",
                         g_hostname, ud.cFileName);
                emit(line);
                count++;
            }
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("UserAssist", count, "users");
    end_artifact();
}

static void Collect_RecentFiles(void)
{
    start_artifact("RecentFiles",
        "Endpoint,User,FileName,TargetPath,CreationTime,LastWriteTime");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;

            char recent[MAX_PATH];
            snprintf(recent, sizeof(recent),
                     "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk",
                     ud.cFileName);

            WIN32_FIND_DATAA fd;
            HANDLE hf = FindFirstFileA(recent, &fd);
            if (hf == INVALID_HANDLE_VALUE) continue;

            int perUser = 0;
            do {
                if (++perUser > 500) break;     /* sanity cap per user */
                char cTime[64], wTime[64];
                filetime_to_iso(&fd.ftCreationTime,  cTime, sizeof(cTime));
                filetime_to_iso(&fd.ftLastWriteTime, wTime, sizeof(wTime));
                char line[1024];
                snprintf(line, sizeof(line), "%s,%s,%s,,%s,%s",
                         g_hostname, ud.cFileName, fd.cFileName, cTime, wTime);
                emit(line);
                count++;
            } while (FindNextFileA(hf, &fd));
            FindClose(hf);
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("RecentFiles", count, "files");
    end_artifact();
}


/* -- filesystem -- */

static void Collect_RecycleBin(void)
{
    start_artifact("RecycleBin",
        "Endpoint,SID,FileName,Size,DeletedTime,OriginalPath");

    DWORD count = 0;
    WIN32_FIND_DATAA sd;
    HANDLE h = FindFirstFileA("C:\\$Recycle.Bin\\*", &sd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(sd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (sd.cFileName[0] != 'S') continue;       /* SID dirs only */

            char p[MAX_PATH];
            snprintf(p, sizeof(p), "C:\\$Recycle.Bin\\%s\\$I*", sd.cFileName);

            WIN32_FIND_DATAA fd;
            HANDLE hf = FindFirstFileA(p, &fd);
            if (hf == INVALID_HANDLE_VALUE) continue;
            do {
                char ts[64];
                filetime_to_iso(&fd.ftLastWriteTime, ts, sizeof(ts));
                char line[1024];
                snprintf(line, sizeof(line), "%s,%s,%s,%lu,%s,",
                         g_hostname, sd.cFileName, fd.cFileName,
                         (unsigned long)fd.nFileSizeLow, ts);
                emit(line);
                count++;
            } while (FindNextFileA(hf, &fd));
            FindClose(hf);
        } while (FindNextFileA(h, &sd));
        FindClose(h);
    }
    progress_done("RecycleBin", count, "items");
    end_artifact();
}

static void Collect_VSS(void)
{
    start_artifact("VSS_Shadows", "Endpoint,ShadowID,CreationTime,VolumeName");

    DWORD count = 0;
    FILE *pipe = _popen("vssadmin list shadows 2>nul", "r");
    if (pipe) {
        char line[1024];
        while (fgets(line, sizeof(line), pipe)) {
            if (strstr(line, "Shadow Copy ID:") ||
                strstr(line, "Creation Time:") ||
                strstr(line, "Shadow Copy Volume:")) {
                char *nl = strchr(line, '\n'); if (nl) *nl = 0;
                char out[1100];
                snprintf(out, sizeof(out), "%s,%s", g_hostname, line);
                emit(out);
                count++;
            }
        }
        _pclose(pipe);
    }
    progress_done("VSS", count, "shadow entries");
    end_artifact();
}

static void Collect_TempFiles(void)
{
    start_artifact("TempFiles",
        "Endpoint,Location,FileName,Size,CreationTime,LastWriteTime,Extension");

    DWORD count = 0;
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("C:\\Windows\\Temp\\*.*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (count++ > 500) break;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char cTime[64], wTime[64];
            filetime_to_iso(&fd.ftCreationTime,  cTime, sizeof(cTime));
            filetime_to_iso(&fd.ftLastWriteTime, wTime, sizeof(wTime));
            const char *ext = strrchr(fd.cFileName, '.'); if (!ext) ext = "";
            char line[2048];
            snprintf(line, sizeof(line),
                     "%s,C:\\Windows\\Temp,%s,%lu,%s,%s,%s",
                     g_hostname, fd.cFileName,
                     (unsigned long)fd.nFileSizeLow, cTime, wTime, ext);
            emit(line);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    progress_done("TempFiles", count, "files");
    end_artifact();
}

static void Collect_UsnJrnl(void)
{
    start_artifact("UsnJrnl",
        "Endpoint,Volume,JournalID,FirstUsn,NextUsn,Note");

    FILE *pipe = _popen("fsutil usn queryjournal C: 2>nul", "r");
    if (pipe) {
        char line[1024];
        char journalId[64] = "", firstUsn[64] = "", nextUsn[64] = "";
        while (fgets(line, sizeof(line), pipe)) {
            if (strstr(line, "Usn Journal ID")) {
                char *c = strchr(line, ':');
                if (c) { c += 2; strncpy(journalId, c, sizeof(journalId) - 1);
                         char *nl = strchr(journalId, '\n'); if (nl) *nl = 0; }
            } else if (strstr(line, "First Usn")) {
                char *c = strchr(line, ':');
                if (c) { c += 2; strncpy(firstUsn, c, sizeof(firstUsn) - 1);
                         char *nl = strchr(firstUsn, '\n'); if (nl) *nl = 0; }
            } else if (strstr(line, "Next Usn")) {
                char *c = strchr(line, ':');
                if (c) { c += 2; strncpy(nextUsn, c, sizeof(nextUsn) - 1);
                         char *nl = strchr(nextUsn, '\n'); if (nl) *nl = 0; }
            }
        }
        if (journalId[0]) {
            char out[1024];
            snprintf(out, sizeof(out),
                     "%s,C:,%s,%s,%s,Use UsnJrnl_Full for full parsing",
                     g_hostname, journalId, firstUsn, nextUsn);
            emit(out);
        }
        _pclose(pipe);
    }
    progress_done("UsnJrnl", 1, "journal queried");
    end_artifact();
}

static void Collect_JumpLists(void)
{
    start_artifact("JumpLists",
        "Endpoint,User,Type,FileName,Size,LastWriteTime");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;

            char p[MAX_PATH];
            snprintf(p, sizeof(p),
                     "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
                     "AutomaticDestinations\\*.automaticDestinations-ms",
                     ud.cFileName);
            WIN32_FIND_DATAA fd;
            HANDLE hf = FindFirstFileA(p, &fd);
            if (hf == INVALID_HANDLE_VALUE) continue;
            do {
                char ts[64];
                filetime_to_iso(&fd.ftLastWriteTime, ts, sizeof(ts));
                char line[1024];
                snprintf(line, sizeof(line),
                         "%s,%s,AutomaticDestinations,%s,%lu,%s",
                         g_hostname, ud.cFileName, fd.cFileName,
                         (unsigned long)fd.nFileSizeLow, ts);
                emit(line);
                count++;
            } while (FindNextFileA(hf, &fd));
            FindClose(hf);
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("JumpLists", count, "files");
    end_artifact();
}

static void Collect_Shellbags(void)
{
    start_artifact("Shellbags", "Endpoint,User,RegistryPath,Note");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;
            char line[1024];
            snprintf(line, sizeof(line),
                     "%s,%s,NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU,"
                     "Parse with ShellBagsExplorer",
                     g_hostname, ud.cFileName);
            emit(line);
            count++;
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("Shellbags", count, "users");
    end_artifact();
}

static void Collect_SRUM(void)
{
    start_artifact("SRUM", "Endpoint,DatabasePath,Size,LastWriteTime,Note");

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\System32\\sru\\SRUDB.dat", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        char ts[64];
        filetime_to_iso(&fd.ftLastWriteTime, ts, sizeof(ts));
        char line[1024];
        snprintf(line, sizeof(line),
                 "%s,C:\\Windows\\System32\\sru\\SRUDB.dat,%lu,%s,Parse with srum-dump",
                 g_hostname, (unsigned long)fd.nFileSizeLow, ts);
        emit(line);
        FindClose(hFind);
    }
    progress_done("SRUM", 1, "database");
    end_artifact();
}


/* -- powershell -- */

static void Collect_PowerShellHistory(void)
{
    start_artifact("PowerShell_History", "Endpoint,User,LineNumber,Command");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;

            char p[MAX_PATH];
            snprintf(p, sizeof(p),
                     "C:\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\"
                     "PSReadLine\\ConsoleHost_history.txt", ud.cFileName);

            FILE *f = fopen(p, "r");
            if (!f) continue;

            char line[4096];
            int  ln = 0;
            while (fgets(line, sizeof(line), f)) {
                ln++;
                char *nl = strchr(line, '\n'); if (nl) *nl = 0;
                char escCmd[8192];
                csv_escape(escCmd, line, sizeof(escCmd));
                char out[8500];
                snprintf(out, sizeof(out), "%s,%s,%d,%s",
                         g_hostname, ud.cFileName, ln, escCmd);
                emit(out);
                count++;
            }
            fclose(f);
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("PowerShell_History", count, "commands");
    end_artifact();
}

static void Collect_PowerShellLogs(void)
{
    start_artifact("PowerShell_Logs",
        "Endpoint,TimeCreated,EventId,ScriptBlockText");

    DWORD count = 0;
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Get-WinEvent -LogName "
        "'Microsoft-Windows-PowerShell/Operational' -MaxEvents 100 "
        "-ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 4104 } | "
        "ForEach-Object { $_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + "
        "($_.Properties[2].Value -replace '`r`n',' ') }\" 2>nul");

    FILE *pipe = _popen(cmd, "r");
    if (pipe) {
        char line[32768];
        while (fgets(line, sizeof(line), pipe)) {
            char *nl = strchr(line, '\n'); if (nl) *nl = 0;
            if (strlen(line) > 10) {
                for (char *p = line; *p; p++) if (*p == '|') *p = ',';
                char out[33000];
                snprintf(out, sizeof(out), "%s,%s", g_hostname, line);
                emit(out);
                count++;
            }
        }
        _pclose(pipe);
    }
    progress_done("PowerShell_Logs", count, "events");
    end_artifact();
}


/* -- network -- */

static void Collect_NetworkConnections(void)
{
    start_artifact("NetworkConnections",
        "Endpoint,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,PID");

    DWORD count = 0;
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) { progress_done("NetworkConnections", 0, "connections"); end_artifact(); return; }

    MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (t && GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *r = &t->table[i];
            struct in_addr la, ra;
            la.s_addr = r->dwLocalAddr;
            ra.s_addr = r->dwRemoteAddr;
            const char *s = "UNKNOWN";
            switch (r->dwState) {
            case MIB_TCP_STATE_LISTEN:     s = "LISTENING";   break;
            case MIB_TCP_STATE_ESTAB:      s = "ESTABLISHED"; break;
            case MIB_TCP_STATE_TIME_WAIT:  s = "TIME_WAIT";   break;
            case MIB_TCP_STATE_CLOSE_WAIT: s = "CLOSE_WAIT";  break;
            }
            char line[1024];
            snprintf(line, sizeof(line), "%s,%s,%u,%s,%u,%s,%lu",
                     g_hostname, inet_ntoa(la), ntohs((u_short)r->dwLocalPort),
                     inet_ntoa(ra), ntohs((u_short)r->dwRemotePort),
                     s, (unsigned long)r->dwOwningPid);
            emit(line);
            count++;
        }
    }
    free(t);
    progress_done("NetworkConnections", count, "connections");
    end_artifact();
}

static void Collect_ListeningPorts(void)
{
    start_artifact("ListeningPorts", "Endpoint,LocalAddress,LocalPort,PID");

    DWORD count = 0, size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size > 0) {
        MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
        if (t && GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                                     TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                if (t->table[i].dwState != MIB_TCP_STATE_LISTEN) continue;
                struct in_addr la; la.s_addr = t->table[i].dwLocalAddr;
                char line[512];
                snprintf(line, sizeof(line), "%s,%s,%u,%lu",
                         g_hostname, inet_ntoa(la),
                         ntohs((u_short)t->table[i].dwLocalPort),
                         (unsigned long)t->table[i].dwOwningPid);
                emit(line);
                count++;
            }
        }
        free(t);
    }
    progress_done("ListeningPorts", count, "ports");
    end_artifact();
}

static void Collect_UDPEndpoints(void)
{
    start_artifact("UDPEndpoints", "Endpoint,LocalAddress,LocalPort,PID");

    DWORD count = 0, size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size > 0) {
        MIB_UDPTABLE_OWNER_PID *t = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
        if (t && GetExtendedUdpTable(t, &size, FALSE, AF_INET,
                                     UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                struct in_addr la; la.s_addr = t->table[i].dwLocalAddr;
                char line[512];
                snprintf(line, sizeof(line), "%s,%s,%u,%lu",
                         g_hostname, inet_ntoa(la),
                         ntohs((u_short)t->table[i].dwLocalPort),
                         (unsigned long)t->table[i].dwOwningPid);
                emit(line);
                count++;
            }
        }
        free(t);
    }
    progress_done("UDPEndpoints", count, "endpoints");
    end_artifact();
}

static void Collect_PortProxy(void)
{
    start_artifact("PortProxy",
        "Endpoint,ListenAddress,ListenPort,ConnectAddress,ConnectPort");

    DWORD count = 0;
    FILE *pipe = _popen("netsh interface portproxy show all 2>nul", "r");
    if (pipe) {
        char line[1024];
        while (fgets(line, sizeof(line), pipe)) {
            if (strstr(line, ".") && strlen(line) > 10) {
                char out[1100];
                snprintf(out, sizeof(out), "%s,%s", g_hostname, line);
                emit(out);
                count++;
            }
        }
        _pclose(pipe);
    }
    progress_done("PortProxy", count, "proxies");
    end_artifact();
}

static void Collect_DNSCache(void)
{
    start_artifact("DNSCache", "Endpoint,Name,Type,Data");

    DWORD count = 0;
    FILE *pipe = _popen("ipconfig /displaydns 2>nul", "r");
    if (pipe) {
        char line[1024], name[256] = "";
        while (fgets(line, sizeof(line), pipe)) {
            if (strstr(line, "Record Name")) {
                char *v = strstr(line, ": ");
                if (v) { v += 2; strncpy(name, v, sizeof(name) - 1);
                         char *nl = strchr(name, '\n'); if (nl) *nl = 0; }
            } else if (strstr(line, "A (Host)") && name[0]) {
                char *v = strstr(line, ": ");
                if (v) {
                    v += 2;
                    char out[1024];
                    snprintf(out, sizeof(out), "%s,%s,A,%s", g_hostname, name, v);
                    char *nl = strchr(out, '\n'); if (nl) *nl = 0;
                    emit(out);
                    count++;
                }
                name[0] = 0;
            }
        }
        _pclose(pipe);
    }
    progress_done("DNSCache", count, "records");
    end_artifact();
}

static void Collect_ARPCache(void)
{
    start_artifact("ARPCache", "Endpoint,IPAddress,MACAddress,Type");

    DWORD count = 0;
    FILE *pipe = _popen("arp -a 2>nul", "r");
    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            if (strlen(line) > 10 && !strstr(line, "Interface") && !strstr(line, "Internet")) {
                char ip[32] = "", mac[32] = "", type[16] = "";
                sscanf(line, "%31s %31s %15s", ip, mac, type);
                if (ip[0] && strchr(ip, '.')) {
                    char out[256];
                    snprintf(out, sizeof(out), "%s,%s,%s,%s",
                             g_hostname, ip, mac, type);
                    emit(out);
                    count++;
                }
            }
        }
        _pclose(pipe);
    }
    progress_done("ARPCache", count, "entries");
    end_artifact();
}

static void Collect_HostsFile(void)
{
    start_artifact("HostsFile", "Endpoint,IP,Hostname");

    DWORD count = 0;
    FILE *f = fopen("C:\\Windows\\System32\\drivers\\etc\\hosts", "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == 0 || *p == '#') continue;

            char ip[64] = "", host[256] = "";
            sscanf(p, "%63s %255s", ip, host);
            if (ip[0] && host[0]) {
                char out[1024];
                snprintf(out, sizeof(out), "%s,%s,%s", g_hostname, ip, host);
                emit(out);
                count++;
            }
        }
        fclose(f);
    }
    progress_done("HostsFile", count, "entries");
    end_artifact();
}

static void Collect_Shares(void)
{
    start_artifact("NetworkShares", "Endpoint,ShareName,Path,Type");

    DWORD count = 0;
    PSHARE_INFO_502 buf, p;
    DWORD entries = 0, total = 0, resume = 0;
    if (NetShareEnum(NULL, 502, (LPBYTE *)&buf,
                     MAX_PREFERRED_LENGTH, &entries, &total, &resume) == ERROR_SUCCESS) {
        p = buf;
        for (DWORD i = 0; i < entries; i++) {
            char shareName[256], path[MAX_PATH];
            wide_to_utf8(p->shi502_netname, shareName, sizeof(shareName));
            wide_to_utf8(p->shi502_path,    path,      sizeof(path));
            char line[2048];
            snprintf(line, sizeof(line), "%s,%s,%s,Disk",
                     g_hostname, shareName, path);
            emit(line);
            count++;
            p++;
        }
        NetApiBufferFree(buf);
    }
    progress_done("NetworkShares", count, "shares");
    end_artifact();
}

static void Collect_FirewallRules(void)
{
    start_artifact("FirewallRules", "Endpoint,Name,Enabled,Direction,Action");

    DWORD count = 0;
    FILE *pipe = _popen("netsh advfirewall firewall show rule name=all 2>nul", "r");
    if (pipe) {
        char line[2048], name[256] = "";
        while (fgets(line, sizeof(line), pipe)) {
            if (strncmp(line, "Rule Name:", 10) == 0) {
                char *v = line + 10;
                while (*v == ' ') v++;
                strncpy(name, v, sizeof(name) - 1);
                char *nl = strchr(name, '\n'); if (nl) *nl = 0;
                char out[1024];
                snprintf(out, sizeof(out), "%s,%s,,,", g_hostname, name);
                emit(out);
                count++;
            }
            if (count && count % 100 == 0) progress("FirewallRules", count, 0, "rules");
        }
        _pclose(pipe);
    }
    progress_done("FirewallRules", count, "rules");
    end_artifact();
}


/* -- browsers --
 * Note: we just point at the SQLite DBs, not parse them. Chrome/Edge lock
 * History while running, so attempting to read inline is unreliable. */

static void enum_browser_history(const char *artifact, const char *relPath, const char *browser)
{
    (void)browser;
    start_artifact(artifact, "Endpoint,User,Profile,Size,LastWriteTime");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;

            char p[MAX_PATH];
            snprintf(p, sizeof(p), "C:\\Users\\%s\\%s", ud.cFileName, relPath);

            WIN32_FIND_DATAA fd;
            HANDLE hf = FindFirstFileA(p, &fd);
            if (hf == INVALID_HANDLE_VALUE) continue;

            char ts[64];
            filetime_to_iso(&fd.ftLastWriteTime, ts, sizeof(ts));
            char line[1024];
            snprintf(line, sizeof(line), "%s,%s,Default,%lu,%s",
                     g_hostname, ud.cFileName,
                     (unsigned long)fd.nFileSizeLow, ts);
            emit(line);
            count++;
            FindClose(hf);
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done(artifact, count, "profiles");
    end_artifact();
}

static void Collect_ChromeHistory(void)
{
    enum_browser_history("Chrome_History",
        "AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "Chrome");
}

static void Collect_EdgeHistory(void)
{
    enum_browser_history("Edge_History",
        "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History", "Edge");
}

static void Collect_FirefoxHistory(void)
{
    /* Firefox profiles are nested under randomly-named dirs; can't share helper */
    start_artifact("Firefox_History", "Endpoint,User,Profile,Size,LastWriteTime");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;

            char ff[MAX_PATH];
            snprintf(ff, sizeof(ff),
                     "C:\\Users\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*",
                     ud.cFileName);

            WIN32_FIND_DATAA pd;
            HANDLE hp = FindFirstFileA(ff, &pd);
            if (hp == INVALID_HANDLE_VALUE) continue;
            do {
                if (!(pd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (!strcmp(pd.cFileName, ".") || !strcmp(pd.cFileName, "..")) continue;

                char places[MAX_PATH];
                snprintf(places, sizeof(places),
                         "C:\\Users\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\%s\\places.sqlite",
                         ud.cFileName, pd.cFileName);

                WIN32_FIND_DATAA fd;
                HANDLE hf = FindFirstFileA(places, &fd);
                if (hf == INVALID_HANDLE_VALUE) continue;

                char ts[64];
                filetime_to_iso(&fd.ftLastWriteTime, ts, sizeof(ts));
                char line[1024];
                snprintf(line, sizeof(line), "%s,%s,%s,%lu,%s",
                         g_hostname, ud.cFileName, pd.cFileName,
                         (unsigned long)fd.nFileSizeLow, ts);
                emit(line);
                count++;
                FindClose(hf);
            } while (FindNextFileA(hp, &pd));
            FindClose(hp);
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("Firefox_History", count, "profiles");
    end_artifact();
}

static void Collect_BrowserExtensions(void)
{
    start_artifact("Browser_Extensions",
        "Endpoint,User,Browser,ExtensionId");

    DWORD count = 0;
    WIN32_FIND_DATAA ud;
    HANDLE h = FindFirstFileA("C:\\Users\\*", &ud);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ud.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!strcmp(ud.cFileName, ".") || !strcmp(ud.cFileName, "..")) continue;

            char p[MAX_PATH];
            snprintf(p, sizeof(p),
                     "C:\\Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\*",
                     ud.cFileName);

            WIN32_FIND_DATAA ed;
            HANDLE he = FindFirstFileA(p, &ed);
            if (he == INVALID_HANDLE_VALUE) continue;
            do {
                if (!(ed.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (!strcmp(ed.cFileName, ".") || !strcmp(ed.cFileName, "..")) continue;
                char line[512];
                snprintf(line, sizeof(line), "%s,%s,Chrome,%s",
                         g_hostname, ud.cFileName, ed.cFileName);
                emit(line);
                count++;
            } while (FindNextFileA(he, &ed));
            FindClose(he);
        } while (FindNextFileA(h, &ud));
        FindClose(h);
    }
    progress_done("Browser_Extensions", count, "extensions");
    end_artifact();
}


/* -- users / auth -- */

static void Collect_LocalUsers(void)
{
    start_artifact("LocalUsers",
        "Endpoint,Username,FullName,Disabled,LastLogon");

    DWORD count = 0;
    USER_INFO_3 *buf = NULL;
    DWORD entries = 0, total = 0, resume = 0;
    if (NetUserEnum(NULL, 3, 0, (LPBYTE *)&buf,
                    MAX_PREFERRED_LENGTH, &entries, &total, &resume) == NERR_Success) {
        for (DWORD i = 0; i < entries; i++) {
            char name[256], full[256];
            wide_to_utf8(buf[i].usri3_name,      name, sizeof(name));
            wide_to_utf8(buf[i].usri3_full_name, full, sizeof(full));
            BOOL dis = (buf[i].usri3_flags & UF_ACCOUNTDISABLE) != 0;
            char line[1024];
            snprintf(line, sizeof(line), "%s,%s,%s,%s,%lu",
                     g_hostname, name, full,
                     dis ? "TRUE" : "FALSE",
                     (unsigned long)buf[i].usri3_last_logon);
            emit(line);
            count++;
        }
        NetApiBufferFree(buf);
    }
    progress_done("LocalUsers", count, "users");
    end_artifact();
}

static void Collect_LocalAdmins(void)
{
    start_artifact("LocalAdministrators", "Endpoint,Member,Type,SID");

    DWORD count = 0;
    LOCALGROUP_MEMBERS_INFO_2 *buf = NULL;
    DWORD entries = 0, total = 0;
    if (NetLocalGroupGetMembers(NULL, L"Administrators", 2, (LPBYTE *)&buf,
                                MAX_PREFERRED_LENGTH, &entries, &total, NULL)
        == NERR_Success) {
        for (DWORD i = 0; i < entries; i++) {
            char dn[512];
            wide_to_utf8(buf[i].lgrmi2_domainandname, dn, sizeof(dn));
            char *sid = NULL;
            ConvertSidToStringSidA(buf[i].lgrmi2_sid, &sid);
            char line[1024];
            snprintf(line, sizeof(line), "%s,%s,User,%s",
                     g_hostname, dn, sid ? sid : "");
            emit(line);
            count++;
            if (sid) LocalFree(sid);
        }
        NetApiBufferFree(buf);
    }
    progress_done("LocalAdmins", count, "members");
    end_artifact();
}

static void Collect_LocalGroups(void)
{
    start_artifact("LocalGroups", "Endpoint,GroupName,Comment");

    DWORD count = 0;
    LOCALGROUP_INFO_1 *buf = NULL;
    DWORD entries = 0, total = 0;
    DWORD_PTR resume = 0;
    if (NetLocalGroupEnum(NULL, 1, (LPBYTE *)&buf, MAX_PREFERRED_LENGTH,
                          &entries, &total, &resume) == NERR_Success) {
        for (DWORD i = 0; i < entries; i++) {
            char name[256], comment[512];
            wide_to_utf8(buf[i].lgrpi1_name,    name,    sizeof(name));
            wide_to_utf8(buf[i].lgrpi1_comment, comment, sizeof(comment));
            char line[1024];
            snprintf(line, sizeof(line), "%s,%s,%s",
                     g_hostname, name, comment);
            emit(line);
            count++;
        }
        NetApiBufferFree(buf);
    }
    progress_done("LocalGroups", count, "groups");
    end_artifact();
}

/* helper to query Security log via PowerShell -- much simpler than EvtQuery */
static void wevt_via_pwsh(const char *artifact, const char *header, const char *cmd)
{
    start_artifact(artifact, header);
    DWORD count = 0;
    FILE *pipe = _popen(cmd, "r");
    if (pipe) {
        char line[4096];
        while (fgets(line, sizeof(line), pipe)) {
            char *nl = strchr(line, '\n'); if (nl) *nl = 0;
            if (strlen(line) > 10) {
                for (char *p = line; *p; p++) if (*p == '|') *p = ',';
                char out[4200];
                snprintf(out, sizeof(out), "%s,%s", g_hostname, line);
                emit(out);
                count++;
            }
        }
        _pclose(pipe);
    }
    progress_done(artifact, count, "events");
    end_artifact();
}

static void Collect_SecurityLogons(void)
{
    wevt_via_pwsh("SecurityLogons",
        "Endpoint,TimeCreated,EventId,LogonType,TargetUser",
        "powershell -Command \"Get-WinEvent -FilterHashtable "
        "@{LogName='Security';Id=4624} -MaxEvents 100 -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + "
        "$_.Properties[8].Value + '|' + $_.Properties[5].Value }\" 2>nul");
}

static void Collect_FailedLogons(void)
{
    wevt_via_pwsh("FailedLogons",
        "Endpoint,TimeCreated,EventId,LogonType,TargetUser",
        "powershell -Command \"Get-WinEvent -FilterHashtable "
        "@{LogName='Security';Id=4625} -MaxEvents 100 -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + "
        "$_.Properties[10].Value + '|' + $_.Properties[5].Value }\" 2>nul");
}

static void Collect_RDPSessions(void)
{
    wevt_via_pwsh("RDPSessions",
        "Endpoint,TimeCreated,EventId,TargetUser",
        "powershell -Command \"Get-WinEvent -FilterHashtable "
        "@{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';"
        "Id=21,25} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object "
        "{ $_.TimeCreated.ToString('o') + '|' + $_.Id + '|' + $_.Properties[0].Value }\" 2>nul");
}


/* -- system / inventory -- */

static void Collect_InstalledSoftware(void)
{
    start_artifact("InstalledSoftware",
        "Endpoint,DisplayName,Version,Publisher");

    DWORD count = 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char  sub[256];
        DWORD len;
        for (;;) {
            len = sizeof(sub);
            if (RegEnumKeyExA(hKey, idx++, sub, &len, NULL, NULL, NULL, NULL)
                != ERROR_SUCCESS) break;

            HKEY hSub;
            if (RegOpenKeyExA(hKey, sub, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
                continue;

            char  name[256] = "", version[64] = "", publisher[256] = "";
            DWORD sz;
            sz = sizeof(name);      RegQueryValueExA(hSub, "DisplayName",    NULL, NULL, (BYTE *)name,      &sz);
            sz = sizeof(version);   RegQueryValueExA(hSub, "DisplayVersion", NULL, NULL, (BYTE *)version,   &sz);
            sz = sizeof(publisher); RegQueryValueExA(hSub, "Publisher",      NULL, NULL, (BYTE *)publisher, &sz);

            if (name[0]) {
                char line[1024];
                snprintf(line, sizeof(line), "%s,%s,%s,%s",
                         g_hostname, name, version, publisher);
                emit(line);
                count++;
            }
            RegCloseKey(hSub);
        }
        RegCloseKey(hKey);
    }
    progress_done("InstalledSoftware", count, "packages");
    end_artifact();
}

static void Collect_USBHistory(void)
{
    start_artifact("USBHistory", "Endpoint,DeviceClass,FriendlyName");

    DWORD count = 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char  cls[256];
        DWORD len;
        for (;;) {
            len = sizeof(cls);
            if (RegEnumKeyExA(hKey, idx++, cls, &len, NULL, NULL, NULL, NULL)
                != ERROR_SUCCESS) break;
            char line[512];
            snprintf(line, sizeof(line), "%s,%s,", g_hostname, cls);
            emit(line);
            count++;
        }
        RegCloseKey(hKey);
    }
    progress_done("USBHistory", count, "devices");
    end_artifact();
}

static void Collect_EnvironmentVars(void)
{
    start_artifact("EnvironmentVariables", "Endpoint,Scope,Name,Value");

    DWORD count = 0;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD idx = 0;
        char  name[256];
        DWORD nameLen;
        BYTE  data[4096];
        DWORD dataLen, type;
        for (;;) {
            nameLen = sizeof(name);
            dataLen = sizeof(data);
            if (RegEnumValueA(hKey, idx++, name, &nameLen, NULL, &type, data, &dataLen)
                != ERROR_SUCCESS) break;
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                char escVal[8192];
                csv_escape(escVal, (char *)data, sizeof(escVal));
                char line[8500];
                snprintf(line, sizeof(line), "%s,System,%s,%s",
                         g_hostname, name, escVal);
                emit(line);
                count++;
            }
        }
        RegCloseKey(hKey);
    }
    progress_done("EnvironmentVars", count, "variables");
    end_artifact();
}

static void Collect_SystemInfo(void)
{
    start_artifact("SystemInfo", "Endpoint,Property,Value");

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD sz;

        sz = sizeof(value);
        if (RegQueryValueExA(hKey, "ProductName", NULL, NULL, (BYTE *)value, &sz) == ERROR_SUCCESS) {
            char line[512];
            snprintf(line, sizeof(line), "%s,ProductName,%s", g_hostname, value);
            emit(line);
        }

        sz = sizeof(value);
        if (RegQueryValueExA(hKey, "CurrentBuild", NULL, NULL, (BYTE *)value, &sz) == ERROR_SUCCESS) {
            char line[512];
            snprintf(line, sizeof(line), "%s,Build,%s", g_hostname, value);
            emit(line);
        }
        RegCloseKey(hKey);
    }

    WCHAR cn[256]; DWORD sz = 256;
    GetComputerNameW(cn, &sz);
    char cnA[256];
    wide_to_utf8(cn, cnA, sizeof(cnA));

    char line[512];
    snprintf(line, sizeof(line), "%s,ComputerName,%s", g_hostname, cnA);
    emit(line);

    progress_done("SystemInfo", 3, "properties");
    end_artifact();
}


/* ---------------------------------------------------------------------------
 * --all driver
 * ------------------------------------------------------------------------ */

static void run_all(void)
{
    fprintf(stderr, "\n=== starting collection (51 artifacts) ===\n");
    if (g_quick)
        fprintf(stderr, "*** QUICK MODE: MFT/USN limited to %lu records ***\n\n",
                (unsigned long)g_quick_limit);

    Collect_ProcessList();
    Collect_NetworkConnections();
    Collect_ListeningPorts();
    Collect_Services();
    Collect_Autoruns();
    Collect_ScheduledTasks();
    Collect_Drivers();
    Collect_LoadedDLLs();
    Collect_DLLs_NoPath();
    Collect_WMIPersistence();
    Collect_StickyKey();
    Collect_IFEO();
    Collect_BITSJobs();
    Collect_Prefetch();
    Collect_ShimCache();
    Collect_Amcache();
    Collect_UserAssist();
    Collect_RecentFiles();
    Collect_RecycleBin();
    Collect_VSS();
    Collect_TempFiles();
    Collect_UsnJrnl();
    Collect_JumpLists();
    Collect_Shellbags();
    Collect_SRUM();
    Collect_PowerShellHistory();
    Collect_PowerShellLogs();
    Collect_UDPEndpoints();
    Collect_PortProxy();
    Collect_DNSCache();
    Collect_ARPCache();
    Collect_HostsFile();
    Collect_Shares();
    Collect_FirewallRules();
    Collect_ChromeHistory();
    Collect_EdgeHistory();
    Collect_FirefoxHistory();
    Collect_BrowserExtensions();
    Collect_LocalUsers();
    Collect_LocalAdmins();
    Collect_LocalGroups();
    Collect_SecurityLogons();
    Collect_FailedLogons();
    Collect_RDPSessions();
    Collect_InstalledSoftware();
    Collect_USBHistory();
    Collect_EnvironmentVars();
    Collect_SystemInfo();

    /* slow ones last so the fast triage data is already on disk if the
     * box dies / EDR kills us mid-NTFS scan */
    fprintf(stderr, "\n=== NTFS deep parsers (require Admin) ===\n");
    Collect_LogFile();
    Collect_UsnJrnlFull();
    Collect_MFT();

    fprintf(stderr, "\n=== collection complete ===\n");
    fprintf(stderr, "output: %s\n", g_outdir);
}


/* ---------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------ */

static void usage(void)
{
    printf("=== win32_collector v" TOOL_VERSION " ===\n");
    printf("Windows DFIR artifact collector\n\n");
    printf("Usage: win32_collector.exe <artifact|--all> [options]\n\n");
    printf("Options:\n");
    printf("  --ui           Output to stdout\n");
    printf("  --download     Save to files in C:\\Windows\\Temp\\<hostname>\n");
    printf("  --both         Both stdout and files\n");
    printf("  --quick        Limit MFT/USN to 50K records (faster)\n\n");
    printf("NTFS Forensics (RAW DISK - REQUIRES ADMIN):\n");
    printf("  MFT              Full MFT - timestamps, deleted files, ADS, timestomping\n");
    printf("  UsnJrnl_Full     USN Journal - file create/delete/rename timeline\n");
    printf("  LogFile          $LogFile - NTFS transaction log status\n\n");
    printf("Categories:\n");
    printf("  Process & DLL: ProcessList, LoadedDLLs, DLLs_NoPath, Drivers\n");
    printf("  Persistence:   Services, Scheduled_Tasks, Autoruns, WMIPer, StickyKey, IFEO, BITSJobs\n");
    printf("  Execution:     Prefetch, ShimCache, Amcache, UserAssist, RecentFiles\n");
    printf("  FileSystem:    RecycleBin, VSS, TempFiles, UsnJrnl, JumpLists, Shellbags, SRUM\n");
    printf("  PowerShell:    PowerShell_History, PowerShell_Logs\n");
    printf("  Network:       NetworkConnections, ListeningPorts, UDPEndpoints, PortProxy, DNSCache,\n");
    printf("                 ARPCache, HostsFile, Shares, FirewallRules\n");
    printf("  Browser:       Chrome_History, Edge_History, Firefox_History, Browser_Extensions\n");
    printf("  Users:         LocalUsers, LocalAdmins, LocalGroups, SecurityLogons, FailedLogons, RDPSessions\n");
    printf("  System:        InstalledSoftware, USBHistory, EnvironmentVars, SystemInfo\n\n");
    printf("Examples:\n");
    printf("  win32_collector.exe --all --download           Full collection\n");
    printf("  win32_collector.exe --all --download --quick   Quick scan (50K limit)\n");
    printf("  win32_collector.exe MFT --both                 Just MFT with progress\n");
}

/* Dispatch table -- way nicer than the long if/else chain we used to have */
struct dispatch_entry {
    const char *name;
    void (*fn)(void);
};

static const struct dispatch_entry g_dispatch[] = {
    { "MFT",                Collect_MFT                },
    { "UsnJrnl_Full",       Collect_UsnJrnlFull        },
    { "LogFile",            Collect_LogFile            },
    { "ProcessList",        Collect_ProcessList        },
    { "LoadedDLLs",         Collect_LoadedDLLs         },
    { "DLLs_NoPath",        Collect_DLLs_NoPath        },
    { "Drivers",            Collect_Drivers            },
    { "Services",           Collect_Services           },
    { "Scheduled_Tasks",    Collect_ScheduledTasks     },
    { "Autoruns",           Collect_Autoruns           },
    { "WMIPer",             Collect_WMIPersistence     },
    { "StickyKey",          Collect_StickyKey          },
    { "IFEO",               Collect_IFEO               },
    { "BITSJobs",           Collect_BITSJobs           },
    { "Prefetch",           Collect_Prefetch           },
    { "ShimCache",          Collect_ShimCache          },
    { "Amcache",            Collect_Amcache            },
    { "UserAssist",         Collect_UserAssist         },
    { "RecentFiles",        Collect_RecentFiles        },
    { "RecycleBin",         Collect_RecycleBin         },
    { "VSS",                Collect_VSS                },
    { "TempFiles",          Collect_TempFiles          },
    { "UsnJrnl",            Collect_UsnJrnl            },
    { "JumpLists",          Collect_JumpLists          },
    { "Shellbags",          Collect_Shellbags          },
    { "SRUM",               Collect_SRUM               },
    { "PowerShell_History", Collect_PowerShellHistory  },
    { "PowerShell_Logs",    Collect_PowerShellLogs     },
    { "NetworkConnections", Collect_NetworkConnections },
    { "ListeningPorts",     Collect_ListeningPorts     },
    { "UDPEndpoints",       Collect_UDPEndpoints       },
    { "PortProxy",          Collect_PortProxy          },
    { "DNSCache",           Collect_DNSCache           },
    { "ARPCache",           Collect_ARPCache           },
    { "HostsFile",          Collect_HostsFile          },
    { "Shares",             Collect_Shares             },
    { "FirewallRules",      Collect_FirewallRules      },
    { "Chrome_History",     Collect_ChromeHistory      },
    { "Edge_History",       Collect_EdgeHistory        },
    { "Firefox_History",    Collect_FirefoxHistory     },
    { "Browser_Extensions", Collect_BrowserExtensions  },
    { "LocalUsers",         Collect_LocalUsers         },
    { "LocalAdmins",        Collect_LocalAdmins        },
    { "LocalGroups",        Collect_LocalGroups        },
    { "SecurityLogons",     Collect_SecurityLogons     },
    { "FailedLogons",       Collect_FailedLogons       },
    { "RDPSessions",        Collect_RDPSessions        },
    { "InstalledSoftware",  Collect_InstalledSoftware  },
    { "USBHistory",         Collect_USBHistory         },
    { "EnvironmentVars",    Collect_EnvironmentVars    },
    { "SystemInfo",         Collect_SystemInfo         },
    { NULL, NULL }
};

int main(int argc, char *argv[])
{
    WSADATA ws;
    WSAStartup(MAKEWORD(2, 2), &ws);

    WCHAR wh[256]; DWORD len = 256;
    GetComputerNameW(wh, &len);
    wide_to_utf8(wh, g_hostname, sizeof(g_hostname));
    snprintf(g_outdir, sizeof(g_outdir), "C:\\Windows\\Temp\\%s", g_hostname);

    if (argc < 2) { usage(); WSACleanup(); return 1; }

    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "--ui"))       g_ui = TRUE;
        else if (!strcmp(argv[i], "--download")) g_save = TRUE;
        else if (!strcmp(argv[i], "--both"))   { g_ui = TRUE; g_save = TRUE; }
        else if (!strcmp(argv[i], "--quick"))    g_quick = TRUE;
    }
    if (!g_ui && !g_save) g_ui = TRUE;

    const char *art = argv[1];

    if (!strcmp(art, "--all")) { run_all(); WSACleanup(); return 0; }

    for (const struct dispatch_entry *d = g_dispatch; d->name; d++) {
        if (!strcmp(art, d->name)) { d->fn(); WSACleanup(); return 0; }
    }

    printf("Unknown artifact: %s\n", art);
    usage();
    WSACleanup();
    return 1;
}
