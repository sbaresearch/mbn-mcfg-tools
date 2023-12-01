## Google
Images can be found here: https://developers.google.com/android/images

For older devices (Nexus 5X, 6P, or Pixel 1) the MBN files can be found in the baseband (radio) image that is located in the outer directory of the image

For newer devices (Pixel 2 to Pixel 5) the MBN files are placed within the vendor.img file; sometimes the vendor.img file has to be unpacked using simg2img

Pixel 6 onwards is no longer using a Snapdragon processor or Qualcomm modem, since they switched to their own Tensor units and cooperate with Samsung for the modem part

## Xiaomi
We downloaded Xiaomi Firmwares from this website: https://xiaomifirmwareupdater.com/firmware/

The MBN files can be found within the NON-HLOS.bin image file

However, not all Xiaomi use Snapdragon/Qualcomm processors/modems, thus there will not be any MBN files for phones that are based on a different architecture (e.g., MediaTek)

## Nokia
Thanks halabtech.com for giving us free access to their database of firmware images.

## LG
Helpful to extract NON-HLOS.bin/modem.bin from kdz firmware: https://github.com/AndroidDumps/Firmware_extractor
