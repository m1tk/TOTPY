# TOTPLY

A toy authentication interface with TOTP MFA authentication implementation

# Running

Install dependencies:
```
pip install -r requirements.txt
```

A secret key must be configured first for flask in `.env`:
```
SECRET_KEY=YOUR_SECRET_KEY
```

Then app can be run:
```
python3 main.py
```
