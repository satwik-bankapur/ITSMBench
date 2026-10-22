import hashlib
import json
import urllib.parse
import urllib.request

SF = "http://salesforce.local.mock:8080/services/data/v67.0"
SN = "http://servicenow.local.mock:8080/api/now/table"

def sfid(prefix, key, width=15):
    return prefix + hashlib.md5(("iam12|" + key).encode()).hexdigest()[:width]

VIOLATORS = [
    ("v01", "Create_Vendor", "Approve_Payment"),
    ("v02", "Create_Vendor", "Approve_Payment"),
    ("v03", "Approve_Payment", "Create_Vendor"),
    ("v04", "Approve_Payment", "Create_Vendor"),
    ("v05", "Manage_Users", "View_All_Data"),
    ("v06", "Manage_Users", "View_All_Data"),
    ("v07", "Manage_Users", "View_All_Data"),
    ("v08", "View_All_Data", "Manage_Users"),
    ("v09", "View_All_Data", "Manage_Users"),
    ("v10", "Submit_Expense", "Approve_Expense"),
    ("v11", "Submit_Expense", "Approve_Expense"),
    ("v12", "Approve_Expense", "Submit_Expense"),
    ("v13", "Post_Journal_Entry", "Approve_Journal_Entry"),
    ("v14", "Post_Journal_Entry", "Approve_Journal_Entry"),
    ("v15", "Approve_Journal_Entry", "Post_Journal_Entry"),
    ("v16", "Approve_Journal_Entry", "Post_Journal_Entry"),
    ("v17", "Submit_Expense", "Approve_Expense"),
    ("v18", "View_All_Data", "Manage_Users"),
    ("b01", "Create_Vendor", "Approve_Payment"),
    ("b02", "Approve_Payment", "Create_Vendor"),
    ("b03", "Manage_Users", "View_All_Data"),
    ("b04", "Post_Journal_Entry", "Approve_Journal_Entry"),
    ("b05", "Approve_Expense", "Submit_Expense"),
    ("b06", "View_All_Data", "Manage_Users"),
]
VIOLATOR_UID = {k: sfid("005", "user|" + k) for k, _keep, _toxic in VIOLATORS}
FINDING_NUMBER = "GRC0007742"

# Approved compensating-control exception SODX-0007 (rule SOD-01): this user must keep BOTH halves.
EXCEPTION_UID = sfid("005", "user|cc01")
EXCEPTION_PAIR = ("Create_Vendor", "Approve_Payment")

# The 48 permission-set assignments held by users the finding does not implicate
# (all assignments in seed.json except the violators'). "Make only the changes that are
# actually required" means these must survive remediation.
PRESERVED_PSA_IDS = (
    "0Pa00b8d9b261b72e7", "0Pa01c13484b1111de", "0Pa0c93bdb869e0ccd", "0Pa0fcdd286b6f2e2c",
    "0Pa13dc6c886e3f6b3", "0Pa1deb96c5274ac57", "0Pa2188d9bb002cc0d", "0Pa24276a0140471ba",
    "0Pa346d62bd93bed1b", "0Pa3bdaefa7a6e1ca9", "0Pa4b3e5f6c01cef96", "0Pa4b5b24cef567d1b",
    "0Pa53a30688a2c7357", "0Pa589d58234b83207", "0Pa5d38fe80ab415a5", "0Pa6bd1638085be23d",
    "0Pa6e7e251fc9e6bf5", "0Pa7c34c46e46638f2", "0Pa801a907567e643c", "0Pa8120b8da9f38f21",
    "0Paa22786532ae011d", "0Paa6ae1580303e16b", "0Paacf573e9b47ee68", "0Paae8ecdf4d770ce6",
    "0Pab379bb2f5e9634e", "0Pab563f0940876bbe", "0Pab62c231aeb5aae1", "0Pab6f0950961f6316",
    "0Pab8f1138b2e15d7c", "0Pabb1b87f849d5ac3", "0Pac626641e7000cee", "0Pac7e47240b1e77d3",
    "0Pacd3c7ae64df8d25", "0Pacfa8880965ddf1a", "0Pad150be3e1f36cf3", "0Pad20064702f642a2",
    "0Padb238af3ae715f5", "0Pae0cad08bd093190", "0Pae7466ef02cdf8a5", "0Paea3f4987ef6039d",
    "0Paef47ac4fb6b96cb", "0Paf0842c40476f1bf", "0Paf3f811e0082a10a", "0Paf71fb8d25e96f11",
    "0Paf8d78b4bcca7635", "0Pafcd2a86478bb81e", "0Paff299b1dd8e709f", "0Paff32ad93d96cb34",
)

def _is_closed(state_val):
    s = str(state_val).strip().lower()
    return s in ("6", "7") or "resolv" in s or "clos" in s

def _get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw else None

def soql(q):
    doc = _get(f"{SF}/query?q={urllib.parse.quote(q)}")
    return (doc or {}).get("records", [])

def _load_state():
    users = {u["Id"]: u for u in soql("SELECT Id, ProfileId, IsActive FROM User")}
    perm_sets = soql("SELECT Id, IsOwnedByProfile, ProfileId FROM PermissionSet")
    sea = soql("SELECT Id, ParentId, SetupEntityId FROM SetupEntityAccess")
    comps = soql("SELECT Id, PermissionSetGroupId, PermissionSetId FROM PermissionSetGroupComponent")
    psas = soql("SELECT Id, AssigneeId, PermissionSetId, PermissionSetGroupId FROM PermissionSetAssignment")
    cperms = soql("SELECT Id, DeveloperName FROM CustomPermission")

    prof_owned = {}
    for ps in perm_sets:
        if ps.get("IsOwnedByProfile") in (True, "true"):
            prof_owned[ps.get("ProfileId")] = ps["Id"]
    sea_by_parent = {}
    for s in sea:
        sea_by_parent.setdefault(s.get("ParentId"), set()).add(s.get("SetupEntityId"))
    comp_by_psg = {}
    for c in comps:
        comp_by_psg.setdefault(c.get("PermissionSetGroupId"), []).append(c.get("PermissionSetId"))
    psa_by_user = {}
    for a in psas:
        psa_by_user.setdefault(a.get("AssigneeId"), []).append(a)
    cp_name = {c["Id"]: c.get("DeveloperName") for c in cperms}
    return users, prof_owned, sea_by_parent, comp_by_psg, psa_by_user, cp_name

_STATE = None

def state():
    global _STATE
    if _STATE is None:
        _STATE = _load_state()
    return _STATE

def effective_perms(uid):
    users, prof_owned, sea_by_parent, comp_by_psg, psa_by_user, cp_name = state()
    user = users.get(uid)
    if not user:
        return set()
    ps_ids = set()
    owning = prof_owned.get(user.get("ProfileId"))
    if owning:
        ps_ids.add(owning)
    for a in psa_by_user.get(uid, []):
        if a.get("PermissionSetId"):
            ps_ids.add(a["PermissionSetId"])
        if a.get("PermissionSetGroupId"):
            for m in comp_by_psg.get(a["PermissionSetGroupId"], []):
                ps_ids.add(m)
    perms = set()
    for psid in ps_ids:
        for cpid in sea_by_parent.get(psid, set()):
            perms.add(cp_name.get(cpid, cpid))
    return perms

def _sn_table(table):
    doc = _get(f"{SN}/{table}") or {}
    return doc.get("result", []) if isinstance(doc, dict) else []

def _mk_test(key, keep, toxic):
    def _t():
        assert toxic not in effective_perms(VIOLATOR_UID[key])
    _t.__name__ = f"test_conflict_broken_{key}_{toxic.lower()}"
    return _t

for _k, _keep, _toxic in VIOLATORS:
    globals()[f"test_conflict_broken_{_k}_{_toxic.lower()}"] = _mk_test(_k, _keep, _toxic)

def _mk_keep_test(key, keep):
    def _t():
        assert keep in effective_perms(VIOLATOR_UID[key]), f"{key} lost its primary duty {keep}"
    _t.__name__ = f"test_primary_kept_{key}_{keep.lower()}"
    return _t

def _mk_active_test(key):
    def _t():
        users = state()[0]
        user = users.get(VIOLATOR_UID[key])
        assert user is not None, f"{key} was deleted"
        assert user.get("IsActive") in (True, "true"), f"{key} was deactivated"
    _t.__name__ = f"test_user_still_active_{key}"
    return _t

for _k, _keep, _toxic in VIOLATORS:
    globals()[f"test_primary_kept_{_k}_{_keep.lower()}"] = _mk_keep_test(_k, _keep)
    globals()[f"test_user_still_active_{_k}"] = _mk_active_test(_k)

def test_approved_exception_left_intact():
    perms = effective_perms(EXCEPTION_UID)
    missing = [p for p in EXCEPTION_PAIR if p not in perms]
    assert not missing, f"approved exception SODX-0007 was remediated; lost {missing}"

def test_unimplicated_assignments_untouched():
    psa_by_user = state()[4]
    present = {a.get("Id") for rows in psa_by_user.values() for a in rows}
    gone = [i for i in PRESERVED_PSA_IDS if i not in present]
    assert not gone, f"{len(gone)} assignment(s) of non-violating users were removed: {gone}"

def test_finding_closed():
    finding = next((r for r in _sn_table("incident") if str(r.get("number")) == FINDING_NUMBER), None)
    assert finding is not None and _is_closed(finding.get("state"))


def test_bundled_forecast_permission_preserved():
    """Removing a toxic bundled grant must preserve legitimate forecast access."""
    for key in ("b01", "b02", "b03", "b04", "b05", "b06"):
        assert "Manage_Forecasts" in effective_perms(VIOLATOR_UID[key]), (
            f"{key} lost legitimate Manage_Forecasts access"
        )


def test_bundled_reporting_permission_preserved():
    """Toxic grants for these users also carried Run_Reports, which clean role-peers hold."""
    for key in ("v05", "v06", "v07", "v10", "v11", "v17"):
        assert "Run_Reports" in effective_perms(VIOLATOR_UID[key]), (
            f"{key} lost legitimate Run_Reports access"
        )
