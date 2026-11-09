"""Generates Windows_MicrosoftDefender_MpEngineDb.smap (SQLECmd map) from one place."""
import json, uuid, sys

ASR = json.load(open('/home/claude/ws2/lookups/asr_rules.json'))['rules']
MAP_ID = sys.argv[1] if len(sys.argv) > 1 else str(uuid.uuid4())
I = ' ' * 16   # SQLECmd guide: 16 spaces before query text


def ft(col, alias):
    """FILETIME (100 ns since 1601) to 'YYYY-MM-DD HH:MM:SS.fffffff' UTC, only in a plausible range."""
    return ("CASE WHEN {c} BETWEEN 119600064000000000 AND 159793632000000000 "
            "THEN printf('%s.%07d', datetime({c} / 10000000 - 11644473600, 'unixepoch'), {c} % 10000000) END AS {a}").format(c=col, a=alias)


def guid(col):
    """16-byte little-endian GUID blob to text."""
    h = 'hex({})'.format(col)
    return ("CASE WHEN length({c}) = 16 THEN lower("
            "substr({h},7,2)||substr({h},5,2)||substr({h},3,2)||substr({h},1,2)||'-'||"
            "substr({h},11,2)||substr({h},9,2)||'-'||substr({h},15,2)||substr({h},13,2)||'-'||"
            "substr({h},17,4)||'-'||substr({h},21,12)) END").format(c=col, h=h)


def asr_case(expr, alias):
    whens = ' '.join("WHEN '{}' THEN '{}'".format(g, n.replace("'", "''")) for g, n in sorted(ASR.items()))
    return ("CASE WHEN {e} IS NULL OR {e} = '' THEN NULL ELSE CASE lower({e}) {w} "
            "ELSE 'Not in Microsoft published ASR list' END END AS {a}").format(e=expr, w=whens, a=alias)


def pid_from(src):
    """PID and process start from text containing 'pid:<n>,ProcessStart:<FILETIME>'."""
    p = "substr({s}, instr({s}, 'pid:') + 4, instr(substr({s}, instr({s}, 'pid:')), ',') - 5)".format(s=src)
    t = "CAST(substr({s}, instr({s}, 'ProcessStart:') + 13, 18) AS INTEGER)".format(s=src)
    return p, t


Q = []

# 1 rolling queues
src = ("CASE WHEN instr(v.EntryTable,'pid:') > 0 THEN v.EntryTable WHEN instr(v.EntryKey,'pid:') > 0 THEN v.EntryKey "
       "WHEN instr(v.EntryValue,'pid:') > 0 THEN v.EntryValue END")
p, t = pid_from(src)
Q.append(('Defender MpEngineDb rolling queues (per-process attack scoring and named queues)', 'RollingQueues', """SELECT
v.ID,
{ins},
{exp},
v.EntryTable AS Queue,
CASE
WHEN v.EntryTable LIKE 'Tech-pid:%' THEN 'Techniques of process (attack scoring)'
WHEN v.EntryTable LIKE 'Tact-pid:%' THEN 'Tactics/rules of process (attack scoring)'
WHEN v.EntryTable LIKE 'InheritedTech-pid:%' THEN 'Inherited techniques (attack scoring)'
WHEN v.EntryTable LIKE 'InheritedTact-pid:%' THEN 'Inherited tactics (attack scoring)'
WHEN v.EntryTable = 'gPidsTable' THEN 'Processes tracked by attack scoring'
WHEN v.EntryTable = 'gTechniquesTable' THEN 'Techniques seen on machine'
WHEN v.EntryTable = 'gTacticsTable' THEN 'Tactics/rules seen on machine'
WHEN v.EntryTable = 'RecentThreatsOnMachine' THEN 'Behaviour detections on machine'
WHEN v.EntryTable LIKE 'RQ_RecentExecDropped%' THEN 'Dropped executable flagged'
ELSE 'Named queue (signature defined)' END AS QueueType,
CASE WHEN {src} IS NOT NULL THEN CAST({p} AS INTEGER) END AS PID,
CASE WHEN {src} IS NOT NULL THEN {t_ft} END AS ProcessStartUTC,
v.EntryKey,
v.EntryValue,
t.Capacity AS QueueCapacity,
t.TimeToLive AS QueueTTLSeconds,
v.InsertTime AS InsertTimeRaw,
v.ExpireTime AS ExpireTimeRaw
FROM RollingQueuesValues v
LEFT JOIN RollingQueuesTables t ON v.EntryTable = ifnull(t.Namespace, '') || t.Name
ORDER BY v.InsertTime ASC;""".format(ins=ft('v.InsertTime', 'InsertTimeUTC'), exp=ft('v.ExpireTime', 'ExpireTimeUTC'),
                                    src=src, p=p, t_ft="printf('%s.%07d', datetime({t} / 10000000 - 11644473600, 'unixepoch'), {t} % 10000000)".format(t=t))))

# 2 persisted context
Q.append(('Defender MpEngineDb persisted context tags and ASR rule state', 'PersistContext', """SELECT
ID,
{ins},
{exp},
FilePath,
Context,
CASE WHEN FilePath LIKE 'AsrRuleStateChangeFor:%' THEN 'ASR rule state (engine)' ELSE 'Path tag (signature)' END AS RecordKind,
{asr},
InsertTime AS InsertTimeRaw,
ExpireTime AS ExpireTimeRaw
FROM AttributePersistContext
ORDER BY InsertTime ASC;""".format(ins=ft('InsertTime', 'InsertTimeUTC'), exp=ft('ExpireTime', 'ExpireTimeUTC'),
                                  asr=asr_case("CASE WHEN FilePath LIKE 'AsrRuleStateChangeFor:%' THEN substr(FilePath, 23) END", 'ASRRule'))))

# 3 file hashes
Q.append(('Defender MpEngineDb real-time protection file hash cache', 'FileHashes', """SELECT
ID,
{its},
printf('%04X-%04X', (VSN >> 16) & 65535, VSN & 65535) AS VolumeSerial,
FileID & 281474976710655 AS MFTEntry,
(FileID >> 48) & 65535 AS MFTSequence,
USN,
hex(SHA1) AS MD5,
hex(MD5) AS SHA1,
hex(SHA256) AS SHA256,
CAST(CASE WHEN instr(CTPH, X'00') > 0 THEN substr(CTPH, 1, instr(CTPH, X'00') - 1) ELSE CTPH END AS TEXT) AS SSDeep,
hex(LSHASH) AS LSHASH,
hex(LSHASHS) AS LSHASHS,
printf('%08X', PartialCRC1 & 4294967295) AS PartialCRC1,
printf('%08X', PartialCRC2 & 4294967295) AS PartialCRC2,
printf('%08X', PartialCRC3 & 4294967295) AS PartialCRC3,
printf('%08X', KCRC1 & 4294967295) AS KCRC1,
printf('%08X', KCRC2 & 4294967295) AS KCRC2,
printf('%08X', KCRC3 & 4294967295) AS KCRC3,
printf('%08X', KCRC3n & 4294967295) AS KCRC3n,
FileID AS FileIDRaw
FROM FileHashes
ORDER BY InstanceTimeStamp ASC;""".format(its=ft('InstanceTimeStamp', 'InstanceTimeStampUTC'))))

# 4 backup process info
Q.append(('Defender MpEngineDb files and processes tracked for ransomware rollback', 'BackupProcessInfo', """SELECT
ID,
{its},
FilePath,
{fst},
CASE WHEN FirstStartTime BETWEEN 119600064000000000 AND 159793632000000000 THEN 'Process start time' ELSE 'Identifier, not a time' END AS FirstStartTimeMeaning,
FirstStartTime AS FirstStartTimeRaw,
NextUSN,
AutomaticRemovalPolicy,
ImpactedCBPNameSpaces
FROM BackupProcessInfo
ORDER BY InstanceTimeStamp ASC;""".format(its=ft('InstanceTimeStamp', 'InstanceTimeStampUTC'), fst=ft('FirstStartTime', 'FirstStartTimeUTC'))))

# 5 lowfi
Q.append(('Defender MpEngineDb LowFi signature hits sent for async cloud lookup', 'LowFiAsync', """SELECT
ID,
{its},
FileName,
SigSeq,
hex(SigSha) AS SigSha,
SigIsSync
FROM FileLowFiAsync
ORDER BY InstanceTimeStamp ASC;""".format(its=ft('InstanceTimeStamp', 'InstanceTimeStampUTC'))))

# 6 schema history
Q.append(('Defender MpEngineDb schema version history (creation and upgrades)', 'SchemaHistory', """SELECT
ID,
Version AS SchemaVersion,
Current,
LastUpdated AS LastUpdatedUTC,
CASE WHEN (SELECT count(*) FROM SQLiteGlobals) = 1 THEN 'Single row: created by an engine already at this version (normal on a recent install, otherwise recreated)'
ELSE 'Upgraded in place' END AS Note
FROM SQLiteGlobals
ORDER BY Version ASC;"""))

# 7 amsi cache
Q.append(('Defender MpEngineDb AMSI scan result cache', 'AmsiFileCache', """SELECT
ID,
ExpirationDate AS ExpirationDateUTC,
PersistId,
hex(PersistIdBlob) AS PersistIdBlob
FROM AmsiFileCache
ORDER BY ExpirationDate ASC;"""))

# 8 process block history
Q.append(('Defender MpEngineDb blocked processes (90 day retention)', 'ProcessBlockHistory', """SELECT
ID,
{ts},
ProcessPath,
TargetPath,
{rid} AS RuleId,
{asr},
IsAudit,
Action,
ProcessTaintReason,
ProcessIntegrity
FROM ProcessBlockHistory
ORDER BY TimeStamp ASC;""".format(ts=ft('TimeStamp', 'TimeStampUTC'), rid=guid('RuleId'), asr=asr_case(guid('RuleId'), 'ASRRule'))))

# 9 behaviour monitored processes
Q.append(('Defender MpEngineDb behaviour monitored processes', 'BmProcessInfo', """SELECT
ID,
{pst},
PID,
ImageFileName,
CommandLineArgs,
PPIDHash,
Flags,
MonitoringFlags_Flags,
{hips} AS HipsInjectionId,
{fg} AS FolderGuardId,
{lsa} AS LsassReadMemId
FROM BmProcessInfo
ORDER BY ProcessStartTime ASC;""".format(pst=ft('ProcessStartTime', 'ProcessStartTimeUTC'), hips=guid('HipsInjectionId'),
                                        fg=guid('FolderGuardId'), lsa=guid('LsassReadMemId'))))

# 10 ransomware detections
Q.append(('Defender MpEngineDb ransomware detections and remediation', 'RansomwareDetections', """SELECT
ID,
DetectionGuid,
{d},
{l},
{p},
{r},
{i},
NextUSN,
ImpactedCBPNameSpaces
FROM RansomwareDetections
ORDER BY DetectionTS ASC;""".format(d=ft('DetectionTS', 'DetectionUTC'), l=ft('LkgTS', 'LastKnownGoodUTC'), p=ft('ProvisionalRemedComplTS', 'ProvisionalRemediationUTC'),
                                   r=ft('RemedComplTS', 'RemediationCompleteUTC'), i=ft('InstanceTimeStamp', 'InstanceTimeStampUTC'))))

# 11 firewall rules from network containment
Q.append(('Defender MpEngineDb firewall rules created by network protection', 'FirewallRules', """SELECT
'Incoming' AS Direction, ID, {e1}, Key, FirewallRuleName FROM NetworkIpFirewallRules
UNION ALL
SELECT
'Outgoing' AS Direction, ID, {e2}, Key, FirewallRuleName FROM NetworkIpFirewallRulesOutgoing
ORDER BY ExpiryUTC ASC;""".format(e1=ft('ExpiryTime', 'ExpiryUTC'), e2=ft('ExpiryTime', 'ExpiryUTC'))))

# 12 atomic counters
Q.append(('Defender MpEngineDb atomic counters set by signatures', 'AtomicCounters', """SELECT
ID,
{ins},
{upd},
{exp},
Namespace,
Name,
Count,
HighCount
FROM AtomicCounters
ORDER BY InsertTime ASC;""".format(ins=ft('InsertTime', 'InsertTimeUTC'), upd=ft('UpdateTime', 'UpdateTimeUTC'), exp=ft('ExpireTime', 'ExpireTimeUTC'))))

# 13 controlled folder access
Q.append(('Defender MpEngineDb Controlled Folder Access paths', 'FolderGuardPaths', """SELECT
ID,
UserId,
{g} AS GUID,
Path
FROM FolderGuardPaths;""".format(g=guid('GUID'))))

lines = [
    'Description: Microsoft Defender MpEngineDb (MetaVault) - decrypted copy of mpenginedb.db',
    'Author: Mato Vlajcic',
    'Email: vlajcic.mato@gmail.com',
    'Id: ' + MAP_ID,
    'Version: 1.0',
    'CSVPrefix: MicrosoftDefender',
    'FileName: mpenginedb_decrypted.db',
    "IdentifyQuery: SELECT count(*) FROM sqlite_master WHERE type='table' AND (name='RollingQueuesValues' OR name='RollingQueuesTables' OR name='AttributePersistContext' OR name='BackupProcessInfo' OR name='FileHashes' OR name='SQLiteGlobals');",
    'IdentifyValue: 6',
    'Queries:',
]
for name, base, sql in Q:
    lines += ['    -', '        Name: ' + name, '        Query: |']
    lines += [I + l for l in sql.split('\n')]
    lines += ['        BaseFileName: ' + base]
lines += [
    '',
    '# Documentation',
    '# The original C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\mpenginedb.db is RC4 encrypted (fixed key from mpengine.dll,',
    '# restarted per page). SQLECmd skips it because the SQLite header is encrypted. Decrypt it first with Decrypt-MpEngineDb.ps1',
    '# or mpenginedb_parser.py, which write mpenginedb_decrypted.db with the -wal already applied, then run SQLECmd on that folder.',
    '# All times are UTC, decoded from Windows FILETIME with 100 ns precision. Raw values are kept in *Raw columns.',
    '# FileHashes: Defender stores MD5 in the column named SHA1 and SHA-1 in the column named MD5. This map outputs them correctly.',
    '# Tech-/Tact- queues hold Defender per-process attack scoring (MITRE ATT&CK technique IDs and rule names, 1 hour lifetime).',
    '# ASR rule names: https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference',
    '# Deleted rows, WAL history and value labels: use mpenginedb_parser.py.',
]
open('/home/claude/ws3/Windows_MicrosoftDefender_MpEngineDb.smap', 'w', newline='\n').write('\n'.join(lines) + '\n')
print('map id', MAP_ID, 'queries', len(Q))
