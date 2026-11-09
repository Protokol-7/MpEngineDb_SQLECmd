<#
.SYNOPSIS
    Decrypts Microsoft Defender's MpEngineDb (mpenginedb.db + -wal) into a normal SQLite
    database that SQLECmd (and any SQLite tool) can open.

.DESCRIPTION
    Defender encrypts every page of mpenginedb.db with RC4 and a fixed 256-byte key taken
    from mpengine.dll. The RC4 stream restarts for every page. On page 1, bytes 16-23 are
    stored in clear and bytes 24 onward use a second run of the stream.

    This script
      - only reads the evidence and hashes it (SHA-256) before and after,
      - decrypts with the known key, or recovers the keystream from the evidence itself
        (-DeriveKey, or automatically when the known key does not match),
      - validates the WAL with SQLite's own rules (salts and checksum chain on the stored
        bytes) and applies only committed frames,
      - writes one plain database, mpenginedb_decrypted.db, with the WAL already applied,
      - writes a log next to it.

    For deleted-row recovery, history per WAL commit and full decoding use
    mpenginedb_parser.py. This script only prepares the database for SQLECmd.

.EXAMPLE
    .\Decrypt-MpEngineDb.ps1 -Path E:\C\ProgramData\Microsoft\Windows Defender\Scans -OutDir D:\case\mpdb
    SQLECmd.exe -d D:\case\mpdb --csv D:\case\sqlecmd

.NOTES
    Works in Windows PowerShell 5.1 and PowerShell 7. Version 1.0.0.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,     # mpenginedb.db or the folder containing it
    [string]$Wal,                                    # WAL file if collected under another name
    [Parameter(Mandatory = $true)][string]$OutDir,
    [switch]$DeriveKey                               # ignore the built-in key, recover it from the evidence
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'

$code = @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

public static class MpEngineDbDecryptor
{
    static readonly byte[] Magic = Encoding.ASCII.GetBytes("SQLite format 3\0");

    // RC4 key from mpengine.dll 1.1.26100.4 (RVA 0xE31A10)
    const string KnownKeyHex =
        "1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54fa" +
        "a21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cbce48e23d053" +
        "71ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe" +
        "3c8a775233557dde13a8b14087cc1bc8f10f6ecdd083a959cff84a9d1d50755e" +
        "3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd029" +
        "1771861a54b4c285a9a3db7aca6d224aeacd621db9f2a22ed1e9e11d75bed7dc" +
        "0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429b" +
        "a495676b8398db2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253";

    public static List<string> Log = new List<string>();

    static byte[] Hex(string h)
    {
        byte[] b = new byte[h.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
        return b;
    }

    public static byte[] Rc4(byte[] key, int n)
    {
        int[] S = new int[256];
        for (int i = 0; i < 256; i++) S[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) & 255;
            int t = S[i]; S[i] = S[j]; S[j] = t;
        }
        byte[] o = new byte[n];
        int x = 0; j = 0;
        for (int k = 0; k < n; k++)
        {
            x = (x + 1) & 255; j = (j + S[x]) & 255;
            int t = S[x]; S[x] = S[j]; S[j] = t;
            o[k] = (byte)S[(S[x] + S[j]) & 255];
        }
        return o;
    }

    static byte[] Slice(byte[] a, int off, int len)
    {
        byte[] r = new byte[len];
        Buffer.BlockCopy(a, off, r, 0, len);
        return r;
    }

    public static byte[] DecryptPage(byte[] data, int pgno, byte[] ks)
    {
        int ps = data.Length;
        byte[] o = new byte[ps];
        if (pgno != 1)
        {
            for (int i = 0; i < ps; i++) o[i] = (byte)(data[i] ^ ks[i]);
            return o;
        }
        for (int i = 0; i < 16; i++) o[i] = (byte)(data[i] ^ ks[i]);
        for (int i = 16; i < 24; i++) o[i] = data[i];
        for (int i = 24; i < ps; i++) o[i] = (byte)(data[i] ^ ks[i - 24]);
        return o;
    }

    static bool IsBtree(int t) { return t == 2 || t == 5 || t == 10 || t == 13; }

    // Recover the keystream from the file: known header plaintext plus zero-filled free space.
    public static byte[] DeriveKeystream(List<byte[]> pages, List<byte[]> frames, int ps)
    {
        List<byte[]> all = new List<byte[]>(pages); all.AddRange(frames);
        List<byte[]> nonroot = new List<byte[]>();
        for (int i = 1; i < pages.Count; i++) nonroot.Add(pages[i]);
        nonroot.AddRange(frames);
        byte[] key = new byte[ps];
        for (int i = 0; i < ps; i++)
        {
            int[] c = new int[256]; int best = 0;
            foreach (byte[] p in all) c[p[i]]++;
            for (int v = 1; v < 256; v++) if (c[v] > c[best]) best = v;
            key[i] = (byte)best;
        }
        for (int i = 0; i < 16; i++) key[i] = (byte)(pages[0][i] ^ Magic[i]);

        Dictionary<int, int> v56 = new Dictionary<int, int>();
        Dictionary<int, int> v34 = new Dictionary<int, int>();
        foreach (byte[] p in nonroot)
        {
            int t = p[0] ^ key[0];
            if (!IsBtree(t)) continue;
            int bestL = 0, gs = 0, ge = 0, s = -1;
            for (int i = 8; i <= ps; i++)
            {
                bool m = i < ps && p[i] == key[i];
                if (m && s < 0) s = i;
                if (!m && s >= 0) { if (i - s > bestL) { bestL = i - s; gs = s; ge = i; } s = -1; }
            }
            if (bestL < 16) continue;
            int hl = (t == 2 || t == 5) ? 12 : 8;
            int k56 = ((p[5] ^ ((ge >> 8) & 255)) << 8) | (p[6] ^ (ge & 255));
            int cnt; v56.TryGetValue(k56, out cnt); v56[k56] = cnt + 1;
            if ((gs - hl) % 2 == 0)
            {
                int n = (gs - hl) / 2;
                int k34 = ((p[3] ^ (n >> 8)) << 8) | (p[4] ^ (n & 255));
                v34.TryGetValue(k34, out cnt); v34[k34] = cnt + 1;
            }
        }
        int bk = -1, bc = 0;
        foreach (KeyValuePair<int, int> kv in v56) if (kv.Value > bc) { bc = kv.Value; bk = kv.Key; }
        if (bk >= 0) { key[5] = (byte)(bk >> 8); key[6] = (byte)(bk & 255); }
        bk = -1; bc = 0;
        foreach (KeyValuePair<int, int> kv in v34) if (kv.Value > bc) { bc = kv.Value; bk = kv.Key; }
        if (bk >= 0) { key[3] = (byte)(bk >> 8); key[4] = (byte)(bk & 255); }

        int[,] votes = new int[ps, 256];
        foreach (byte[] p in nonroot)
        {
            int t = p[0] ^ key[0];
            if (!IsBtree(t)) continue;
            int n = ((p[3] ^ key[3]) << 8) | (p[4] ^ key[4]);
            int cs = ((p[5] ^ key[5]) << 8) | (p[6] ^ key[6]); if (cs == 0) cs = 65536;
            int pe = ((t == 2 || t == 5) ? 12 : 8) + 2 * n;
            if (pe <= cs && cs <= ps) for (int i = pe; i < cs; i++) votes[i, p[i]]++;
        }
        for (int i = 8; i < ps; i++)
        {
            int best = -1, bv = 0;
            for (int v = 0; v < 256; v++) if (votes[i, v] > bv) { bv = votes[i, v]; best = v; }
            if (best >= 0) key[i] = (byte)best;
        }
        for (int i = 0; i < 8; i++) key[i] = (byte)(pages[0][i] ^ Magic[i]);
        return key;
    }

    static uint U32BE(byte[] b, int o) { return (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]); }

    static void Cksum(byte[] b, int off, int len, bool big, ref uint s0, ref uint s1)
    {
        for (int i = off; i < off + len; i += 8)
        {
            uint a, c;
            if (big) { a = U32BE(b, i); c = U32BE(b, i + 4); }
            else { a = BitConverter.ToUInt32(b, i); c = BitConverter.ToUInt32(b, i + 4); }
            s0 = unchecked(s0 + a + s1);
            s1 = unchecked(s1 + c + s0);
        }
    }

    public static string Run(string dbPath, string walPath, string outPath, bool deriveOnly)
    {
        Log.Clear();
        byte[] db = File.ReadAllBytes(dbPath);
        int ps = (db[16] << 8) | db[17]; if (ps == 1) ps = 65536;
        if (ps < 512 || (ps & (ps - 1)) != 0 || db.Length % ps != 0)
            throw new Exception("Not a MetaVault/SQLite file (page size field " + ps + ", size " + db.Length + ")");
        List<byte[]> pages = new List<byte[]>();
        for (int o = 0; o < db.Length; o += ps) pages.Add(Slice(db, o, ps));

        // WAL frames, validated as SQLite does, on the stored bytes
        List<int> fPg = new List<int>(); List<int> fCommit = new List<int>(); List<byte[]> fData = new List<byte[]>();
        int validUntil = 0, lastCommitIdx = 0, lastCommitSize = 0, total = 0;
        if (!string.IsNullOrEmpty(walPath))
        {
            byte[] w = File.ReadAllBytes(walPath);
            uint magic = w.Length >= 32 ? U32BE(w, 0) : 0;
            if (magic == 0x377F0682 || magic == 0x377F0683)
            {
                bool big = (magic & 1) == 1;
                uint s0 = 0, s1 = 0;
                Cksum(w, 0, 24, big, ref s0, ref s1);
                bool ok = s0 == U32BE(w, 24) && s1 == U32BE(w, 28);
                uint salt1 = U32BE(w, 16), salt2 = U32BE(w, 20);
                int wps = (int)U32BE(w, 8);
                if (wps != ps) Log.Add("WARNING: WAL page size " + wps + " differs from database page size " + ps);
                int off = 32, idx = 0;
                while (off + 24 + wps <= w.Length)
                {
                    idx++; total++;
                    int pg = (int)U32BE(w, off), commit = (int)U32BE(w, off + 4);
                    fPg.Add(pg); fCommit.Add(commit); fData.Add(Slice(w, off + 24, wps));
                    if (ok)
                    {
                        if (U32BE(w, off + 8) != salt1 || U32BE(w, off + 12) != salt2) { ok = false; Log.Add("WAL frame " + idx + ": salt mismatch, older WAL generation from here"); }
                        else
                        {
                            Cksum(w, off, 8, big, ref s0, ref s1); Cksum(w, off + 24, wps, big, ref s0, ref s1);
                            if (s0 != U32BE(w, off + 16) || s1 != U32BE(w, off + 20)) { ok = false; Log.Add("WAL frame " + idx + ": checksum chain broken, frames from here are not applied"); }
                            else { validUntil = idx; if (commit != 0) { lastCommitIdx = idx; lastCommitSize = commit; } }
                        }
                    }
                    off += 24 + wps;
                }
                Log.Add("WAL: " + total + " frames, valid chain to frame " + validUntil + ", last commit at frame " + lastCommitIdx);
            }
            else Log.Add("WARNING: WAL header not recognised, WAL ignored");
        }
        else Log.Add("WARNING: no WAL file, newest changes may be missing");

        // keystream
        byte[] ks = null; string how;
        bool plain = true;
        for (int i = 0; i < 16; i++) if (db[i] != Magic[i]) { plain = false; break; }
        if (plain) { how = "none: database is plain SQLite (codec disabled)"; }
        else
        {
            how = null;
            if (!deriveOnly)
            {
                byte[] cand = Rc4(Hex(KnownKeyHex), ps);
                bool m = true;
                for (int i = 0; i < 16; i++) if ((db[i] ^ cand[i]) != Magic[i]) { m = false; break; }
                if (m) { ks = cand; how = "known key (mpengine.dll 1.1.26100.4)"; }
            }
            if (ks == null)
            {
                List<byte[]> fr = new List<byte[]>();
                for (int i = 0; i < fData.Count; i++) if (fPg[i] != 1) fr.Add(fData[i]);
                ks = DeriveKeystream(pages, fr, ps);
                how = "recovered from the evidence (known header + free space)";
            }
        }
        Log.Add("Protection: " + (plain ? how : "RC4 page codec, keystream " + how));

        // build final image: decrypted pages + committed WAL frames
        List<byte[]> img = new List<byte[]>();
        for (int i = 0; i < pages.Count; i++) img.Add(plain ? pages[i] : DecryptPage(pages[i], i + 1, ks));
        int nPages = pages.Count;
        for (int i = 0; i < lastCommitIdx; i++)
        {
            int pg = fPg[i];
            while (img.Count < pg) img.Add(new byte[ps]);
            img[pg - 1] = plain ? fData[i] : DecryptPage(fData[i], pg, ks);
            if (fCommit[i] != 0) nPages = fCommit[i];
        }
        if (lastCommitIdx > 0) Log.Add("Applied " + lastCommitIdx + " committed WAL frames, database size " + nPages + " pages");

        byte[] head = img[0];
        for (int i = 0; i < 16; i++) if (head[i] != Magic[i]) throw new Exception("Decryption failed: header does not match");
        // the result is a rollback-journal database: clear WAL mode (bytes 18/19 = 1) so no -wal is expected
        head[18] = 1; head[19] = 1;
        using (FileStream fs = new FileStream(outPath, FileMode.CreateNew, FileAccess.Write))
        {
            for (int i = 0; i < nPages; i++) fs.Write(img[i], 0, ps);
        }
        Log.Add("Written: " + outPath + " (" + nPages + " pages)");
        return how;
    }
}
'@

if (-not ('MpEngineDbDecryptor' -as [type])) { Add-Type -TypeDefinition $code -Language CSharp }

function Write-Log([string]$m) {
    $line = '{0} UTC {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $m
    Write-Host $line
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
}

if (Test-Path -LiteralPath $Path -PathType Container) { $Path = Join-Path $Path 'mpenginedb.db' }
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Database not found: $Path" }
$Path = (Resolve-Path -LiteralPath $Path).Path
if (-not $Wal -and (Test-Path -LiteralPath ($Path + '-wal'))) { $Wal = $Path + '-wal' }
if ($Wal) { $Wal = (Resolve-Path -LiteralPath $Wal).Path }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$out = Join-Path $OutDir 'mpenginedb_decrypted.db'
if (Test-Path -LiteralPath $out) { throw "Output exists, refusing to overwrite: $out" }
$script:LogFile = Join-Path $OutDir 'Decrypt-MpEngineDb.log'

Write-Log "Decrypt-MpEngineDb $ScriptVersion, PowerShell $($PSVersionTable.PSVersion)"
$evidence = @($Path) + @($Wal | Where-Object { $_ })
$before = @{}
foreach ($e in $evidence) {
    $h = (Get-FileHash -LiteralPath $e -Algorithm SHA256).Hash
    $before[$e] = $h
    Write-Log ("Evidence {0}  size {1}  SHA-256 {2}" -f $e, (Get-Item -LiteralPath $e).Length, $h)
}

try {
    [void][MpEngineDbDecryptor]::Run($Path, $Wal, $out, [bool]$DeriveKey)
} finally {
    foreach ($l in [MpEngineDbDecryptor]::Log) { Write-Log $l }
}

$changed = $false
foreach ($e in $evidence) {
    if ((Get-FileHash -LiteralPath $e -Algorithm SHA256).Hash -ne $before[$e]) { $changed = $true; Write-Log "ERROR: evidence changed: $e" }
}
if (-not $changed) { Write-Log 'Evidence unchanged after run (SHA-256 verified)' }
Write-Log ("Output SHA-256 {0}" -f (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash)
Write-Log "Next: SQLECmd.exe -d `"$OutDir`" --csv <output folder>"
