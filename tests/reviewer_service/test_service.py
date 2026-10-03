import sys, hashlib, json, base64
from pathlib import Path
from unittest.mock import Mock
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "engineering-gate"), str(ROOT / "engineering-gate" / "engineering_gate_core")]
from reviewer_service.service import (MAX_MESSAGE_BYTES, validate_request, decide_and_sign, Ledger, responses_body, parse_model_output, load_private_key)
from engineering_gate_core.models import Plan, NormalizedOperation, OperationKind, AcceptanceCriterion, WorkspaceIdentity, MutationProposal
from engineering_gate_core.workflow import canonical_plan_digest, canonical_mutation_proposal_digest, mutation_argument_digest
from engineering_gate_core.signed_authorization import verify_signed_verdict, ReviewerPublicKey, SignedMutationVerdict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def fixture_request():
    plan=Plan("objective",(NormalizedOperation(OperationKind.WRITE,"out.txt","write"),),(AcceptanceCriterion("c1","ok","check"),),("verify",),(),"/tmp/work",WorkspaceIdentity("/tmp/work",1,2),())
    plan_obj={"objective":plan.objective,"operations":[{"kind":"write","target":"out.txt","rationale":"write"}],"acceptance_criteria":[{"criterion_id":"c1","description":"ok","verification_procedure":"check"}],"verification":["verify"],"exclusions":[],"workspace_root":"/tmp/work","workspace_identity":{"canonical_path":"/tmp/work","device":1,"inode":2},"verification_commands":[]}
    pd=str(canonical_plan_digest(plan)); content="actual contents"
    proposal=MutationProposal("prop","task",0,pd,plan.operations[0],mutation_argument_digest(content),"because",None)
    proposal_obj={"proposal_id":"prop","task_id":"task","revision":0,"plan_digest":pd,"operation":{"kind":"write","target":"out.txt","rationale":"write"},"argument_digest":proposal.argument_digest,"rationale":"because","diff_digest":None}
    packet={"task_id":"task","task_objective":"objective","inspection_evidence":{"evidence_id":"i","description":"inspected"},"analysis":{"evidence_id":"a","description":"analysis","passed":None,"provenance":"agent_claim"},"plan":plan_obj,"blast_radius":{"evidence_id":"b","description":"limited","passed":None,"provenance":"agent_claim"},"plan_review":{"verdict":"approved","findings":[]},"plan_revision":0,"plan_digest":pd,"workspace_identity":{"canonical_path":"/tmp/work","device":1,"inode":2},"approval_request_id":"approval","profile_id":"default"}
    return {"schema_version":1,"review_request_id":"a"*32,"task_id":"task","plan_revision":0,"plan_digest":pd,"approval_packet":packet,"approval_packet_digest":hashlib.sha256(json.dumps(packet,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest(),"proposal":proposal_obj,"proposal_digest":canonical_mutation_proposal_digest(proposal),"mutation_arguments":{"content":content},"implementer_id":"engineering-gate-hermes"}

def test_task_objective_can_be_refined_but_both_objectives_are_reviewed():
    request=fixture_request()
    request["approval_packet"]["task_objective"]="Original task: create and verify a safe artifact"
    request["approval_packet_digest"]=hashlib.sha256(json.dumps(request["approval_packet"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    assert validate_request(request) is request
    body=responses_body(request)
    instructions=body["input"][0]["content"][0]["text"]
    context=json.loads(body["input"][1]["content"][0]["text"])
    assert context["approval_packet"]["task_objective"]=="Original task: create and verify a safe artifact"
    assert context["approval_packet"]["plan"]["objective"]=="objective"
    assert "not required to be verbatim identical" in instructions
    assert "materially conflicts" in instructions


def test_plan_review_packet_is_exact_gate_json_shape():
    changes=(
        lambda review: review.update(extra="not allowed"),
        lambda review: review.update(findings="not-an-array"),
        lambda review: review.update(findings=[{"finding":"not a string"}]),
        lambda review: review.update(verdict="needs_changes"),
    )
    for change in changes:
        request=fixture_request()
        change(request["approval_packet"]["plan_review"])
        request["approval_packet_digest"]=hashlib.sha256(json.dumps(request["approval_packet"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        with pytest.raises(ValueError):
            validate_request(request)


def test_task_objective_and_plan_objective_are_digest_bound():
    request=fixture_request()
    request["approval_packet"]["task_objective"]="different approved task context"
    request["approval_packet_digest"]=hashlib.sha256(json.dumps(request["approval_packet"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    validate_request(request)
    request["approval_packet"]["task_objective"]="tampered after digest"
    with pytest.raises(ValueError):
        validate_request(request)


def test_review_request_and_packet_cannot_be_self_consistently_cross_task_bound():
    request=fixture_request()
    # Simulate the pre-fix shape: a packet for task A paired with a fully self-consistent task B.
    request["task_id"]="task-B"
    request["approval_packet"]["task_id"]="task-A"
    request["approval_packet_digest"]=hashlib.sha256(json.dumps(request["approval_packet"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    request["proposal"]["task_id"]="task-B"
    proposal=MutationProposal(request["proposal"]["proposal_id"],"task-B",0,request["plan_digest"],
        NormalizedOperation(OperationKind.WRITE,"out.txt","write"),request["proposal"]["argument_digest"],"because",None)
    request["proposal_digest"]=canonical_mutation_proposal_digest(proposal)
    with pytest.raises(ValueError):
        validate_request(request)

def test_rejects_unbound_legacy_packet_even_when_outer_and_proposal_match():
    request=fixture_request()
    request["approval_packet"].pop("task_id")
    request["task_id"]="task-B"
    request["proposal"]["task_id"]="task-B"
    proposal=MutationProposal(request["proposal"]["proposal_id"],"task-B",0,request["plan_digest"],
        NormalizedOperation(OperationKind.WRITE,"out.txt","write"),request["proposal"]["argument_digest"],"because",None)
    request["proposal_digest"]=canonical_mutation_proposal_digest(proposal)
    request["approval_packet_digest"]=hashlib.sha256(json.dumps(request["approval_packet"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    with pytest.raises(ValueError):
        validate_request(request)


def test_rejects_extra_caller_verdict():
    req=fixture_request(); req["verdict"]="approve"
    with pytest.raises(ValueError): validate_request(req)

def test_signs_service_owned_positive_verdict_and_binds_exact_model_request(tmp_path):
    req=fixture_request(); key=Ed25519PrivateKey.generate(); raw=key.private_bytes_raw(); pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    ledger=Ledger(tmp_path/"ledger.sqlite")
    bodies=[]
    def transport(body):
        bodies.append(body); return {"status":"completed","model":"gpt-6.1-sol","output":[{"type":"message","status":"completed","content":[{"type":"output_text","text":json.dumps({"decision":"approve","findings":[]})}]}],"usage":{"input_tokens":10,"output_tokens":2}}
    result=decide_and_sign(req,transport=transport,private_key=raw,key_id="key-1",ledger=ledger)
    assert set(result)=={"canonical_payload_b64","signature_b64"}
    body=bodies[0]
    assert body["model"]=="gpt-6.1-sol" and body["store"] is False and body["tools"]==[] and body["tool_choice"]=="none" and body["reasoning"]=={"effort":"high"}
    assert body["max_output_tokens"]==2048 and body["text"]["format"]["strict"] is True
    payload=base64.b64decode(result["canonical_payload_b64"]); signature=base64.b64decode(result["signature_b64"])
    verified=verify_signed_verdict(SignedMutationVerdict(payload,signature),ReviewerPublicKey("key-1","engineering-gate-reviewer-v1","openai:gpt-6.1-sol",pub),now=__import__('datetime').datetime.now(__import__('datetime').timezone.utc),implementer_id="engineering-gate-hermes")
    assert verified.verdict=="approve"
    with pytest.raises(Exception): ledger.reserve(req["review_request_id"],"x","x","x")

def test_malformed_and_major_findings_fail_closed():
    from reviewer_service.service import MODEL
    with pytest.raises(Exception): parse_model_output({"status":"completed","model":MODEL,"output":[{"type":"message","status":"completed","content":[{"type":"output_text","text":"not json"}]}]})
    assert parse_model_output({"status":"completed","model":MODEL,"output":[{"type":"message","status":"completed","content":[{"type":"output_text","text":json.dumps({"decision":"approve","findings":[{"severity":"major","finding":"unsafe"}]})}]}]})=="reject"

def test_rejects_bad_binding_and_implementer():
    r=fixture_request(); r["proposal_digest"]="0"*64
    with pytest.raises(ValueError): validate_request(r)
    r=fixture_request(); r["implementer_id"]="caller"
    with pytest.raises(ValueError): validate_request(r)

def test_key_permissions_and_symlink_are_rejected(tmp_path):
    p=tmp_path/"key"; p.write_bytes(b"x"*32); p.chmod(0o644)
    with pytest.raises(ValueError): load_private_key(p)
    p.chmod(0o600); link=tmp_path/"link"; link.symlink_to(p)
    with pytest.raises(ValueError): load_private_key(link)

def test_refusal_is_not_a_verdict():
    from reviewer_service.service import MODEL
    with pytest.raises(ValueError): parse_model_output({"status":"completed","model":MODEL,"output":[{"type":"message","status":"completed","content":[{"type":"refusal","refusal":"no"}]}]})

def test_error_timeout_fail_closed_and_keeps_reservation(tmp_path):
    req=fixture_request(); ledger=Ledger(tmp_path/"timeout.sqlite"); key=Ed25519PrivateKey.generate().private_bytes_raw()
    def timeout(_body): raise TimeoutError("sensitive transport detail")
    with pytest.raises(ValueError,match="review unavailable"):
        decide_and_sign(req,transport=timeout,private_key=key,key_id="k",ledger=ledger)
    row=ledger.db.execute("SELECT outcome,reserved FROM reviews WHERE request_id=?",(req["review_request_id"],)).fetchone()
    assert row[0]=="error" and row[1]>0
    with pytest.raises(Exception): decide_and_sign(req,transport=timeout,private_key=key,key_id="k",ledger=ledger)

def test_tampered_content_packet_types_and_task_bindings_are_rejected():
    for change in (lambda r:r["mutation_arguments"].update(content="tampered"),
                   lambda r:r["approval_packet"].update(extra=True),
                   lambda r:r.update(task_id="other"),
                   lambda r:r["approval_packet"].update(workspace_identity=None)):
        request=fixture_request(); change(request)
        if "approval_packet" in request:
            packet=request["approval_packet"]
            request["approval_packet_digest"]=hashlib.sha256(json.dumps(packet,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        with pytest.raises(ValueError): validate_request(request)

def test_reject_decision_remains_reject_and_response_has_no_signer_fields(tmp_path):
    req=fixture_request(); key=Ed25519PrivateKey.generate().private_bytes_raw(); ledger=Ledger(tmp_path/"reject.sqlite")
    output={"status":"completed","model":"gpt-6.1-sol","output":[{"type":"message","status":"completed","content":[{"type":"output_text","text":json.dumps({"decision":"reject","findings":[]})}]}],"usage":{"input_tokens":1,"output_tokens":1}}
    result=decide_and_sign(req,transport=lambda _:output,private_key=key,key_id="k",ledger=ledger)
    from engineering_gate_core.signed_authorization import _pairs_no_duplicates
    payload=json.loads(base64.b64decode(result["canonical_payload_b64"]),object_pairs_hook=_pairs_no_duplicates)
    assert payload["verdict"]=="reject"
    assert set(payload)=={"schema_version","signature_algorithm","key_id","review_id","reviewer_id","reviewer_provider","implementer_id","task_id","plan_revision","plan_digest","proposal_digest","verdict","reviewed_at"}
    assert base64.b64encode(key).decode() not in json.dumps(result)

def test_responses_contract_forbids_tools_and_pins_structured_output():
    body=responses_body(fixture_request())
    assert body["tools"]==[] and body["tool_choice"]=="none" and body["store"] is False
    assert body["text"]["format"]["type"]=="json_schema" and body["text"]["format"]["strict"] is True
    assert body["text"]["format"]["schema"]["additionalProperties"] is False

def test_response_binds_full_review_context_and_rejects_noncompleted_or_wrong_model():
    from reviewer_service.service import parse_model_output, MODEL
    request=fixture_request()
    body=responses_body(request)
    context=json.loads(body["input"][1]["content"][0]["text"])
    assert context["task_id"]==request["task_id"]
    assert context["plan_revision"]==request["plan_revision"]
    assert context["plan_digest"]==request["plan_digest"]
    assert context["implementer_id"]==request["implementer_id"]
    assert context["mutation_arguments"]==request["mutation_arguments"]
    valid={"status":"completed","model":MODEL,"output":[{"type":"message","status":"completed","content":[{"type":"output_text","text":json.dumps({"decision":"approve","findings":[]})}]}]}
    assert parse_model_output(valid)=="approve"
    for bad in ({**valid,"status":"incomplete"},{**valid,"status":"failed"},{**valid,"model":"other-model"},{**valid,"output":[{"type":"message","status":"incomplete","content":[{"type":"output_text","text":"{}"}]}]}):
        with pytest.raises(ValueError): parse_model_output(bad)

def test_audit_log_is_structured_and_redacted(tmp_path,caplog):
    import logging
    from reviewer_service.service import decide_and_sign, Ledger
    request=fixture_request()
    key=Ed25519PrivateKey.generate().private_bytes_raw()
    response={"status":"completed","model":"gpt-6.1-sol","output":[{"type":"message","status":"completed","content":[{"type":"output_text","text":json.dumps({"decision":"approve","findings":[]})}]}],"usage":{"input_tokens":9,"output_tokens":2}}
    ledger=Ledger(tmp_path/"audit.sqlite")
    with caplog.at_level(logging.INFO,logger="engineering_gate.reviewer_service"):
        decide_and_sign(request,transport=lambda _:response,private_key=key,key_id="k",ledger=ledger)
    assert caplog.records
    record=json.loads(caplog.records[-1].getMessage())
    assert set(record)=={"request_id","model","decision","outcome","request_digest","proposal_digest","packet_digest","input_tokens","output_tokens","cost_usd"}
    assert record["request_id"]==request["review_request_id"] and record["decision"]=="approve"
    assert "actual contents" not in caplog.text and "actual contents" not in str(record)
    row=ledger.db.execute("SELECT * FROM reviews").fetchone()
    assert row is not None and "actual contents" not in repr(row)
    assert ledger.db.execute("PRAGMA table_info(reviews)").fetchall()

def test_http_transport_rejects_noncanonical_endpoint():
    from reviewer_service.service import http_transport
    import reviewer_service.service as service
    called=[]
    class Response:
        def __enter__(self): return self
        def __exit__(self,*_): pass
        def read(self,_): return b"{}"
    def fake_urlopen(req,**kwargs): called.append((req.full_url,req.get_header("Authorization"))); return Response()
    service.urlopen=fake_urlopen
    assert http_transport("synthetic",{})=={}
    assert called==[("https://api.openai.com/v1/responses","Bearer synthetic")]

def test_service_cli_requires_explicit_socket_identity_and_has_no_endpoint_override():
    import os, subprocess
    env=os.environ.copy(); env["PYTHONPATH"]=str(ROOT/"engineering-gate")
    help_run=subprocess.run([sys.executable,"-m","reviewer_service.service","--help"],env=env,text=True,capture_output=True,check=True)
    assert "--client-uid" in help_run.stdout and "--socket-gid" in help_run.stdout
    assert "--endpoint" not in help_run.stdout
    rejected=subprocess.run([sys.executable,"-m","reviewer_service.service","--socket","/tmp/x","--ledger","/tmp/y","--private-key","/tmp/z","--api-key-file","/tmp/k","--key-id","k","--client-uid","1","--socket-gid","1","--endpoint","http://127.0.0.1:9"],env=env,text=True,capture_output=True)
    assert rejected.returncode==2 and "unrecognized arguments: --endpoint" in rejected.stderr
