#!/usr/bin/env python3
"""
Test script for VirusTotal integration
"""

import asyncio
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "app"))

from app.analyzers.link_analyzer import LinkAnalyzer
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.models import LinkData, AttachmentData
from app.config import settings


async def test_virustotal_url():
    """Test VirusTotal URL analysis"""
    print("🔗 Testing VirusTotal URL Analysis")
    print("=" * 50)

    if not settings.VIRUSTOTAL_API_KEY:
        print("❌ VIRUSTOTAL_API_KEY not set in environment")
        return

    analyzer = LinkAnalyzer()

    # Test with a known malicious URL (EICAR test)
    test_urls = [
        "http://malware.wicar.org/data/eicar.com",
        "https://www.google.com",
        "http://amaz0n-verify.tk/login",
    ]

    for url in test_urls:
        print(f"\n🌐 Testing URL: {url}")
        try:
            result = await analyzer.analyze_single_url(url)
            print(f"   Reputation Score: {result.reputation_score}/100")
            print(f"   Is Malicious: {result.is_malicious}")
            print(f"   Is Phishing: {result.is_phishing}")
            print(f"   Risk Factors: {len(result.risk_factors)}")
            if result.risk_factors:
                for factor in result.risk_factors[:3]:  # Show first 3
                    print(f"     - {factor}")
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")


async def test_virustotal_file():
    """Test VirusTotal file hash analysis"""
    print("\n📁 Testing VirusTotal File Analysis")
    print("=" * 50)

    if not settings.VIRUSTOTAL_API_KEY:
        print("❌ VIRUSTOTAL_API_KEY not set in environment")
        return

    analyzer = AttachmentAnalyzer()

    # Test with known file hashes
    test_files = [
        {
            "filename": "eicar.com",
            "hash": "44d88612fea8a8f36de82e1278abb02f",  # EICAR test file
        },
        {
            "filename": "clean_file.txt",
            "hash": "d41d8cd98f00b204e9800998ecf8427e",  # Empty file hash
        },
        {
            "filename": "suspicious.exe",
            "hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # Known malware
        },
    ]

    for file_info in test_files:
        print(f"\n📄 Testing file: {file_info['filename']}")
        print(f"   Hash: {file_info['hash'][:16]}...")
        try:
            result = await analyzer.analyze_single_attachment(
                file_info["filename"], file_info["hash"]
            )
            print(f"   Is Malicious: {result.is_malicious}")
            print(f"   Hash Reputation: {result.hash_reputation}")
            print(f"   Risk Factors: {len(result.risk_factors)}")
            if result.risk_factors:
                for factor in result.risk_factors[:3]:  # Show first 3
                    print(f"     - {factor}")
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")


async def test_full_email_analysis():
    """Test full email analysis with VirusTotal integration"""
    print("\n📧 Testing Full Email Analysis")
    print("=" * 50)

    # Load test email
    import json

    try:
        with open("tests/sample_emails/phishing_example.json", "r") as f:
            email_data = json.load(f)

        # Convert to proper models
        from app.models import EmailData, LinkData, AttachmentData

        links = [LinkData(**link) for link in email_data.get("links", [])]
        attachments = [
            AttachmentData(**att) for att in email_data.get("attachments", [])
        ]

        email = EmailData(
            from_address=email_data["from"],
            to=email_data["to"],
            subject=email_data["subject"],
            body=email_data["body"],
            headers=email_data["headers"],
            links=links,
            attachments=attachments,
            timestamp=email_data["timestamp"],
            messageId=email_data["messageId"],
        )

        # Test link analysis
        if links:
            link_analyzer = LinkAnalyzer()
            print(f"\n🔗 Analyzing {len(links)} links...")
            link_results = await link_analyzer.analyze_links(links)
            print(f"   Found {len(link_results)} link risk factors")
            for result in link_results[:2]:  # Show first 2
                print(f"     - {result.risk}: {result.description}")

        # Test attachment analysis
        if attachments:
            att_analyzer = AttachmentAnalyzer()
            print(f"\n📎 Analyzing {len(attachments)} attachments...")
            att_results = await att_analyzer.analyze_attachments(attachments)
            print(f"   Found {len(att_results)} attachment risk factors")
            for result in att_results[:2]:  # Show first 2
                print(f"     - {result.risk}: {result.description}")

    except FileNotFoundError:
        print("❌ Test email file not found")
    except Exception as e:
        print(f"❌ Error in full analysis: {str(e)}")


async def main():
    """Run all tests"""
    print("🛡️  SecureGuard VirusTotal Integration Test")
    print("=" * 60)

    if not settings.VIRUSTOTAL_API_KEY:
        print("⚠️  Warning: VIRUSTOTAL_API_KEY not set")
        print("   Set your VirusTotal API key in backend/.env")
        print("   Some tests will be skipped")
    else:
        print(f"✅ VirusTotal API key configured: {settings.VIRUSTOTAL_API_KEY[:8]}...")

    print()

    await test_virustotal_url()
    await test_virustotal_file()
    await test_full_email_analysis()

    print("\n🎉 Testing completed!")
    print("\nNote: VirusTotal API has rate limits:")
    print("   - Free tier: 4 requests/minute")
    print("   - Some results may be cached")


if __name__ == "__main__":
    asyncio.run(main())
