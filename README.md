# dlc-decrypter

A simple library to decode dlc files:
https://de.wikipedia.org/wiki/JDownloader#Download_Link_Container (german)

## Example
For an example have a look at the main.rs

## About DLC
DLC = Download Link Container. It's a crappy file format. But it's often used for downloading.
Step 1: Split the file in 2 parts. Part 1 is the data. Part 2 are the last 88 chars from the file are the data_key.
Step 2: Send the data_key to the service.jdownloader.org (with an app specific id) to get an other key.
Step 3: Remove the surrounding <rc></rc> from the returned key and base64 decode the value.
Step 4: AES/CBC decrypt the data from Step 3 with an app specific key/iv.
Step 5: Base64 decode the data part from Step 1.
Step 6: AES/CBC decrypt the data from Step 5 with the result from Step 4 as key/iv.
Step 7: Base64 decode the result from Step 6. Now you have an XML.
Step 8: The values in the xml are Base64 encoded. So you have to decode the values.
