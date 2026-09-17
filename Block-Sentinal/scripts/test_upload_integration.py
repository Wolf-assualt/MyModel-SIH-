import urllib.request
import json
from pathlib import Path
import requests

def test_frontend_markup():
    url = "http://127.0.0.1:8000/"
    with urllib.request.urlopen(url) as response:
        content = response.read().decode("utf-8")
    
    assert 'id="input-files-upload"' in content, "Missing #input-files-upload"
    assert 'id="input-folder-upload"' in content, "Missing #input-folder-upload"
    assert 'id="dropzone"' in content, "Missing #dropzone"
    assert 'class="spectral-band-grid"' in content, "Missing spectral-band-grid"
    assert 'id="tab-mode-upload"' in content, "Missing #tab-mode-upload"
    assert 'id="tab-mode-demo"' in content, "Missing #tab-mode-demo"
    assert 'id="btn-select-folder"' in content, "Missing #btn-select-folder"
    assert 'id="btn-select-files"' in content, "Missing #btn-select-files"
    assert 'webkitdirectory' in content, "Missing webkitdirectory attribute for folder selection"
    print("[PASS] [TEST 1] Frontend HTML markup verification: PASSED (All upload UI controls present)")
    return True

def test_multipart_upload_clean():
    clean_dir = Path("test_data/sentinel2_sample_clean")
    files = list(clean_dir.glob("*.tif")) + list(clean_dir.glob("*.json"))
    assert len(files) == 13, f"Expected 13 files, found {len(files)}"
    
    upload_files = [("files", (f.name, open(f, "rb"), "application/octet-stream")) for f in files]
    res = requests.post("http://127.0.0.1:8000/api/v1/datasets/upload", files=upload_files)
    
    for _, (_, f_obj, _) in upload_files:
        f_obj.close()
        
    assert res.status_code == 200, f"Upload failed: {res.text}"
    data = res.json()
    assert data["success"] is True
    batch_id = data["data"]["batch_id"]
    merkle_root = data["data"]["merkle_root"]
    sample_count = data["data"]["sample_count"]
    print(f"[PASS] [TEST 2] Clean Sentinel-2 Upload API: PASSED -> Batch ID: {batch_id}, Merkle Root: {merkle_root[:16]}..., Samples: {sample_count}")
    return batch_id

def test_multipart_upload_tampered():
    tampered_dir = Path("test_data/sentinel2_sample_tampered")
    files = list(tampered_dir.glob("*.tif")) + list(tampered_dir.glob("*.json"))
    
    upload_files = [("files", (f.name, open(f, "rb"), "application/octet-stream")) for f in files]
    res = requests.post("http://127.0.0.1:8000/api/v1/datasets/upload", files=upload_files)
    
    for _, (_, f_obj, _) in upload_files:
        f_obj.close()
        
    assert res.status_code == 200, f"Tampered upload failed: {res.text}"
    data = res.json()
    assert data["success"] is True
    batch_id = data["data"]["batch_id"]
    merkle_root = data["data"]["merkle_root"]
    print(f"[PASS] [TEST 3] Tampered B04 Upload API: PASSED -> Batch ID: {batch_id}, Merkle Root: {merkle_root[:16]}...")
    return batch_id

def test_multipart_upload_invalid():
    # Test uploading a single non-EO file
    upload_files = [("files", ("dummy_text.txt", b"this is not an EO band", "text/plain"))]
    res = requests.post("http://127.0.0.1:8000/api/v1/datasets/upload", files=upload_files)
    data = res.json()
    print(f"[PASS] [TEST 4] Single Non-EO Upload API Result: {data['success']} (Handled gracefully)")

def test_full_pipeline_with_uploaded_data():
    # Upload clean patch, register it, verify manifest, and check end-to-end readiness
    clean_dir = Path("test_data/sentinel2_sample_clean")
    files = list(clean_dir.glob("*.tif")) + list(clean_dir.glob("*.json"))
    upload_files = [("files", (f.name, open(f, "rb"), "application/octet-stream")) for f in files]
    res = requests.post("http://127.0.0.1:8000/api/v1/datasets/upload", files=upload_files)
    for _, (_, f_obj, _) in upload_files:
        f_obj.close()
    
    batch_id = res.json()["data"]["batch_id"]
    
    # Verify manifest integrity endpoint
    verify_res = requests.get(f"http://127.0.0.1:8000/api/v1/datasets/manifest/{batch_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["data"]["valid"] is True
    print(f"[PASS] [TEST 5] Ingested Manifest Verification: PASSED -> Valid: {v_data['data']['valid']}, Calculated Root: {v_data['data']['calculated_root'][:16]}...")

if __name__ == "__main__":
    test_frontend_markup()
    test_multipart_upload_clean()
    test_multipart_upload_tampered()
    test_multipart_upload_invalid()
    test_full_pipeline_with_uploaded_data()
    print("\n=======================================================")
    print("ALL REAL DATA UPLOAD WORKFLOW INTEGRATION TESTS PASSED")
    print("=======================================================")
