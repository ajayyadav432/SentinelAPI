import asyncio
from backend.ingestion.spec_parser import SpecParser

async def test_parsing():
    spec_path = "backend/sandbox/crapi_openapi.yaml"
    with open(spec_path, "r") as f:
        spec_text = f.read()

    spec_dict = SpecParser.parse_content(spec_text)
    parsed = SpecParser.parse_spec(spec_dict, default_base_url="http://127.0.0.1:8000/sandbox-target")
    print(f"SUCCESS: Parsed {len(parsed.endpoints)} endpoints for '{parsed.title}' (version {parsed.version})")
    for ep in parsed.endpoints:
        print(f" - [{ep.method}] {ep.path} (has_id={ep.has_path_id}, cat={ep.category})")

if __name__ == "__main__":
    asyncio.run(test_parsing())
