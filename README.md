# idOS-daily-check-in
______________________
### You can auto complete daily check in quest on idOS platform with your refersh and bearer tokens.
> Easy to use

# Registration
+ Visit https://app.idos.network/?ref=F0E2547E
+ Create a profile
+ Connect your wallet
+ Complete face verification

# Installation Guide [Linux/Ubuntu]
1. Clone the repository
```
git clone https://github.com/Quincy-seun/idOS-daily-check-in.git
cd idOS-daily-check-in
```
2. Install dependencies
```
pip install -r requirements.txt
```
or force install
```
pip install --ignore-installed -r requirements.txt --break-system-packages
```
3. Configure the script
+ Inspect dashboard with F12 or right-click, Inspect
+ Go to Application
+ Local Storage, drop down arrow
+ https://app.idos.network
+ Click on auth_jwts and copy your access token and refresh token
+ Fill in bearer.txt and refresh.txt respectively
+ Fill valid proxies in proxy.txt (optional)

4. Run the script
```
python main.py
```
Support me
EVM:
```
0x5534B7a62A7313f78a2B526300b29342BdeE2580
```
Solana: 
```
F2Ye1aoW3xXUDDFFDDQiymiwGwH4Ld1FHLZS4K3FAsFH
```
