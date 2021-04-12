#!/usr/bin/env bash
#pip3 install pyopenssl --user
#pip3 install -r requirements.txt --user
export APP_CONFIG_FILE=config.py
#secret keys in flask are used to generate session tokens using weak keys means that session tokens can 
#be forged. So I used UUID4 here
export SECRET_KEY=6ce700a7-ae09-4e4d-9af8-5399bb6e1b75
python3 app.py
