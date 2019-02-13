# -*- coding: utf-8 -*-
import socket
import json
import sys


class Client:
    HOST = "api.openweathermap.org"
    PORT = 80

    def __init__(self, api_key, city):
        self.api_key = api_key
        self.city = city

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((Client.HOST, Client.PORT))
        req = "GET /data/2.5/weather?q={0}&APPID={1} HTTP/1.1\n".format(self.city, self.api_key)
        req += "Host: {0}\n".format(Client.HOST)
        req += "\n"
        s.send(req.encode())
        result = s.recv(2048)
        s.close()
        return result.decode()

    def to_json(self):
        response = self.connect()
        response = response.split("\r\n\r\n")[1]
        json_object = json.loads(response)
        return json_object

    def prepare_info(self):
        r = self.to_json()
        info = {}
        info["overcast"] = r["weather"][0]["description"]
        info["temp"] = round(r["main"]["temp"] - 273.15, 1)
        info["humidity"] = r["main"]["humidity"]
        info["pressure"] = r["main"]["pressure"]
        info["wind-speed"] = r["wind"]["speed"]
        try:
            info["wind-deg"] = r["wind"]["deg"]
        except KeyError:
            info["wind-deg"] = "n/a"
        return info


if __name__ == "__main__":
    # TODO: nepovolit i trislovne nazvy? Palma de Mallorca
    if len(sys.argv) == 4:
        city = sys.argv[2] + " " + sys.argv[3]
    else:
        city = sys.argv[2]
    if len(sys.argv) > 4:
        print("Usage: python xchlup08.py <api_key> <city>", file=sys.stderr)
        sys.exit(1)
    c = Client(sys.argv[1], city)
    info_to_print = c.prepare_info()
    print(
        "{0}\novercast {1}\ntemp:{2}\xb0C\nhumidity:{3}%\npressure:{4} hPa\nwind-speed: {5}km/h\nwind-deg: {6}".format(
            c.city,
            info_to_print["overcast"],
            info_to_print["temp"],
            info_to_print["humidity"],
            info_to_print["pressure"],
            info_to_print["wind-speed"],
            info_to_print["wind-deg"],
        )
    )
