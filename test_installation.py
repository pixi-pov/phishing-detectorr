import sys

def test_imports():
    packages = {
        'flask': 'Flask',
        'numpy': 'NumPy', 
        'pandas': 'Pandas',
        'sklearn': 'Scikit-Learn',
        'requests': 'Requests',
        'whois': 'python-whois',
        'tldextract': 'tldextract',
        'bs4': 'BeautifulSoup4',
        'joblib': 'Joblib'
    }
    
    failed = []
    for module, name in packages.items():
        try:
            __import__(module)
            print(f"✅ {name}")
        except ImportError as e:
            print(f"❌ {name}: {e}")
            failed.append(name)
    
    print(f"\nPython version: {sys.version}")
    
    if not failed:
        print("\n🎉 All packages installed successfully! Ready for Step 2.")
        return True
    else:
        print(f"\n⚠️ Failed to install: {', '.join(failed)}")
        return False

if __name__ == "__main__":
    test_imports()