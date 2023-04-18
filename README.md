# OTP-generator
Simple OTP generator in **Python3** for generating varying length OTP codes

### Note
> I am not a security expert, so this may not be the most secure OTP generator. Use with caution.

## Usage

```
from otp_generator import OTPGenerator

otp_gen = OTPGenerator(digits=6)
otp = otp_gen.generate_otp()
```


### Credits
> https://pyauth.github.io/pyotp/
