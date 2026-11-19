import requests


def fetch(url):
    session = requests.Session()
    return session.get(url, verify=False)
