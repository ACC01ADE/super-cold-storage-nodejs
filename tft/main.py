# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-

import sys
import time
import subprocess
import digitalio
import board
from PIL import Image, ImageDraw, ImageFont
from adafruit_rgb_display import st7789

authorizationFont = ImageFont.truetype("/srv/www/nodejs/tft/sourcecode.ttf", 26)
fingerprintFont = ImageFont.truetype("/srv/www/nodejs/tft/sourcecode.ttf", 26)
white = "#FFFFFF"
black = "#000000"

# Configuration for CS and DC pins (these are FeatherWing defaults on M0/M4):
cs_pin = digitalio.DigitalInOut(board.CE0)
dc_pin = digitalio.DigitalInOut(board.D25)
reset_pin = None

# Configure buttons
buttonA = digitalio.DigitalInOut(board.D23)
buttonB = digitalio.DigitalInOut(board.D24)
buttonA.switch_to_input()
buttonB.switch_to_input()

# Config for display baudrate (default max is 24mhz):
BAUDRATE = 64000000

# Setup SPI bus using hardware SPI:
spi = board.SPI()

# Create the ST7789 display:
disp = st7789.ST7789(
    spi,
    cs=cs_pin,
    dc=dc_pin,
    rst=reset_pin,
    baudrate=BAUDRATE,
    width=135,
    height=240,
    x_offset=53,
    y_offset=40,
)

# Configure backlight
backlight = digitalio.DigitalInOut(board.D22)
backlight.switch_to_output()
backlight.value = True

height = disp.width  # we swap height/width to rotate it to landscape!
width = disp.height
rotation = 90

# Set current display view
currentDisplay = 'splash'

def splash():
  image = Image.new("RGB", (width, height))
  draw = ImageDraw.Draw(image)
  draw.rectangle((0, 0, width, height), outline=0, fill=black)
  disp.image(image, rotation)
  image = Image.open("/srv/www/nodejs/tft/splash.jpg")
  disp.image(image, rotation)

def authorization(authText):
  image = Image.new("RGB", (width, height))
  draw = ImageDraw.Draw(image)
  draw.rectangle((0, 0, width, height), outline=0, fill=black)
  disp.image(image, rotation)
  draw.text((8, 4), authText, font=authorizationFont, fill=white)
  disp.image(image, rotation)

def fingerprint(fingerprintText):
  image = Image.new("RGB", (width, height))
  draw = ImageDraw.Draw(image)
  draw.rectangle((0, 0, width, height), outline=0, fill=black)
  disp.image(image, rotation)
  draw.text((8, 4), fingerprintText, font=fingerprintFont, fill=white)
  disp.image(image, rotation)

print('Number of arguments:', len(sys.argv), 'arguments.')
print('Argument List:', str(sys.argv))

splash()
time.sleep(2)

while True:
  if not buttonA.value and not buttonB.value:
    if backlight.value == True: # toggle backlight
      backlight.value = False
      splash()
      currentDisplay = 'splash'
    else:
      backlight.value = True
    time.sleep(0.25)
  if backlight.value == True:
    if buttonB.value and not buttonA.value:  # just button A pressed
      if currentDisplay == 'splash':
        # we need to toggle fingerprint
        fingerprint(sys.argv[1])
        currentDisplay = 'fingerprint'
      else:
        splash()
        currentDisplay = 'splash'
      time.sleep(0.25)
    if buttonA.value and not buttonB.value:  # just button B pressed
      if currentDisplay == 'splash':
        # we need to toggle fingerprint
        authorization(sys.argv[2])
        currentDisplay = 'authorization'
      else:
        splash()
        currentDisplay = 'splash'
      time.sleep(0.25)
  time.sleep(0.1)
