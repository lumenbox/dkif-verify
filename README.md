Simple DKIF verification service
=======================================================
dkif-verify is simple API which can be used to do a DKIF verificaiton

## Docker
You can build your own Docker image (Dockerfile is in the repo) or use our image form dockerhub: lumenbox/dkif-verify:latest

## Example calls

### Gather informatio abour a domain
$ curl http://<hostname>/lumenbox.org
{
  "control": "*", 
  "keys": [
    "GAI55SVFTWSRNRFQGPUD264OF6UDD2O3MGUBDZWFR2GRJ3WOCTFUUMLP"
  ], 
  "request": 200, 
  "toml": "FEDERATION_SERVER=\"https://lumenbox.org/federation\"\n", 
  "url": "https://lumenbox.org/federation"
}

### Verify signature and provide information about the process
$ curl http://<hostname>/donation*lumenbox.org
{
  "control": "*", 
  "keys": [
    "GAI55SVFTWSRNRFQGPUD264OF6UDD2O3MGUBDZWFR2GRJ3WOCTFUUMLP"
  ], 
  "record": {
    "account_id": "GDYUXO2Q7MJJNKAL54FM3CHY35ZQYDYJLUKT5ITHBNNSSDHTAL6OIBOX", 
    "memo": "", 
    "signature": "/xQ3lWuEgCx5NvnBBa03L7Rbo6yKCasL6hydpTeJKnWzTWNXo7mSXADfMc2SPEQbFF72TZeBciqu/Aiwox/bBw==", 
    "stellar_address": "donation*lumenbox.org"
  }, 
  "request": 200, 
  "toml": "FEDERATION_SERVER=\"https://lumenbox.org/federation\"\n", 
  "url": "https://lumenbox.org/federation", 
  "validate": {
    "signed": "GAI55SVFTWSRNRFQGPUD264OF6UDD2O3MGUBDZWFR2GRJ3WOCTFUUMLP"
  }
}

