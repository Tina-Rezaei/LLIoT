import re
import requests
from tqdm import tqdm

API_URL = "https://www.variotdbs.pl/api/vulns/"
TOKEN = "your_github_token"

CVEPAT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def extract_cves_from_record(rec):
    cves = set()
    categories = set()

    # 1) Primary field
    if isinstance(rec.get("cve"), str) and CVEPAT.fullmatch(rec["cve"]):
        cves.add(rec["cve"].upper())
        if isinstance(rec.get("iot_taxonomy"), dict):
            categories = set(rec["iot_taxonomy"]["data"][0]["category"])
            print(categories)
        return cves, categories
    else:
        return None, None


def fetch_all_cves():
    headers = {"Authorization": f"Token {TOKEN}", "Accept": "application/json"}
    params = {
        "jsonld": "false",
        "since": "1970-01-01T00:00:00+00:00",
        "before": "2099-12-31T23:59:59+00:00",
    }

    url = API_URL
    seen = set()

    while url:
        r = requests.get(url, headers=headers, params=params if url == API_URL else None, timeout=60)
        r.raise_for_status()
        data = r.json()

        for rec in tqdm(data.get("results", [])):
            cve_id, category = extract_cves_from_record(rec)
            if cve_id:
                seen.add((tuple(cve_id), tuple(category)))
            else:
                print(f"⚠️ Warning: No CVE found in record ID {rec.get('id')}")
                with open("varIoT_no_cve.log", "a") as f:
                    f.write(f"Record ID {rec.get('id')} has no CVE\n")
        url = data.get("next")
    return sorted(seen)

if __name__ == "__main__":
    all_cves = fetch_all_cves()
    print(f"Total unique CVEs: {len(all_cves)}")
    for cve in all_cves:
        print(cve)

    with open("varIoT_cves.txt", "w") as f:
        for cve in all_cves:
            f.write(f"{cve}\n")
