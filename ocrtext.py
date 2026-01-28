import pytesseract
from PIL import Image
import cv2
import os

"""
Page segmentation modes: 
0 Orientation and script detection (OSD) only
1 Automatic page segmentation with OSD. ‘
2 Automatic page segmentation, but no OSD, or OCR.
3 Fully automatic page segmentation, but no OSD. (Default)
4 Assume a single column of text of variable sizes.
5 Assume a single uniform block of vertically aligned text.
6 Assume a single uniform block of textJ
7 Treat the image as a single text line.
8 Treat the image as a single word.
9 Treat the image as a single word in a circle.
10 Treat the image as a single character.
11 Sparse text. Find as much text as possible in no particular order.
12 Sparse text with OSD.
13 Raw line. Treat the image as a single text line, bypassing hacks that are Tesseract—specific.
"""

"""
OCR Engine Mode
0    Legacy engine only.
1    Neural nets LSTM engine only.
2    Legacy + LSTM engines.
3    Default, based on what is available.
"""

myconfig = r"--psm 6 --oem 3"

text = pytesseract.image_to_string(Image.open(r"C:\Users\techn\Downloads\test files for ISPJ\ocrjpgtext.jpg"), config=myconfig)
print(text)