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

    def get_request(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as err:
            print("Socket creation failed with error {0}".format(err))
            exit(1)
        s.connect((Client.HOST, Client.PORT))
        req = "GET /data/2.5/weather?q={0}&APPID={1} HTTP/1.1\n".format(self.city, self.api_key)
        req += "Host: {0}\n".format(Client.HOST)
        req += "\n"
        s.send(req.encode())
        result = s.recv(2048)
        s.close()
        return result.decode()

    def convert_to_json(self):
        response = self.get_request()
        response = response.split("\r\n\r\n")[1]
        get_status_code = json.loads(response.split("\r\n\r\n")[0])
        self.check_response(get_status_code)
        json_object = json.loads(response)
        return json_object

    @staticmethod
    def check_response(get_status_code):
        if get_status_code["cod"] != 200:
            print(get_status_code["message"])
            exit(1)

    def prepare_weather_info(self):
        json_response = self.convert_to_json()
        info = {}
        try:
            info["overcast"] = json_response["weather"][0]["main"].lower()
        except KeyError:
            print("Weather is not available for this city")
            exit(1)
        info["temp"] = round(json_response["main"]["temp"] - 273.15, 1)
        info["humidity"] = json_response["main"]["humidity"]
        info["pressure"] = json_response["main"]["pressure"]
        info["wind-speed"] = json_response["wind"]["speed"]
        try:
            info["wind-deg"] = json_response["wind"]["deg"]
        except KeyError:
            info["wind-deg"] = "n/a"
        return info


def main():
    api_key = sys.argv[1]
    city = sys.argv[2:]
    city = " ".join(city)
    c = Client(api_key, city)
    current_weather = c.prepare_weather_info()
    print(
        "{0}\novercast {1}"
        "\ntemp: {2}°C"
        "\nhumidity: {3}%"
        "\npressure: {4}hPa"
        "\nwind-speed: {5}km/h"
        "\nwind-deg: {6}".format(
            c.city,
            current_weather["overcast"],
            current_weather["temp"],
            current_weather["humidity"],
            current_weather["pressure"],
            current_weather["wind-speed"],
            current_weather["wind-deg"],
        )
    )


if __name__ == "__main__":
    main()
