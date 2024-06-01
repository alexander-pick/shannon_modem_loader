# Simple Shannon Baseband Loader for IDA Pro

This is a simple firmware loader plugin to load Samsung Exynos "Shannon" modem images in [IDA Pro](https://hex-rays.com/ida-pro/). This loader is designed to be lean and easy to understand. It should work with most Samsung Exynos modem images containing a TOC header. These can be found e.g. in updates for Exynos based phones. The typical file name is `modem.bin`. Sometimes the images are compressed using lz4, uncompress them before loading using lz4 utility present on most Linux distros. 

# How To Use This Loader

To use the loader just install `shannon_load.py` inside your [IDA Pro](https://hex-rays.com/ida-pro/)'s loader folder and the rest of the python files into the [IDA Pro](https://hex-rays.com/ida-pro/) python folder. `install.sh` will assist you with this task, if you want to do it manually please take a look inside. For [IDA Pro](https://hex-rays.com/ida-pro/) 8.3 and 8.4 the default installation directory should be detected by default. Otherwise you can specify the installation directory as the first parameter to the script. 

`./install.sh ~/your-ida-installdir/`

Once installed open a `modem.bin` file extracted from an OTA update in [IDA Pro](https://hex-rays.com/ida-pro/). The loader should detect the TOC format and load the image accordingly. The postprocessor script will add additional segment information after the initial analysis has finished. Adding the segments right from the start will confuse and slow down the analysis process.

The postprocessing module does most of the magic and it will take a bit to run, please be patient. All steps the post processor performs are in the individual files copied to `<IDAHOME>/python/`. You can use them as individual python modules if needed. See the post processor for details. A complete analysis of a modem image takes about 30 minutes to complete on average hardware.

## How The Loader Works

The TOC header is a simple structure the loader will read to create a database of the file with proper aligned segments and entry points. For more insights just look at the code contained in this reponsitory. 

The loader will recognize a TOC based Shannon modem binary and load it. After basic processing and initial auto analysis, exessive post-processing is performed. The post processing workflow will perform the following tasks:

* restore debug trace entries and structures
* rename functions based on various string references
* rename supplementary services functions (`ss_*`) based on debug log functions
* identify the hardware and mpu init function
* restore the mpu table and map memory accordingly
* identify the scatter loader
* perform scatter loading and decompression ([LZ77-like](https://developer.arm.com/documentation/dui0474/j/linker-optimization-features/how-compression-is-applied) compression scheme)
* find the platform abstraction layer init function and restore all tasks

After that the `idb` should be ready to go.

# About Samsung Shannon 

Shannon is an IC series by Samsung LSI. Most noteable product in the series is the Shannon baseband processor. Shannon is the name of a range of ICs and not the name of the modem itself. You might find other Shannon ICs made by Samsung. A typical set of Shannon ICs consists of a baseband, RF transciever, powermanagement and a envelope tracking IC. All of them have different part numbers. E.g. Shannon baseband is 5300, the RF transciever is 5510, PMIC is 5200 and so on. So don't get confused, these are all different parts. You won't find much about Shannon on Samsungs website, they refer to the baseband as [Exynos Modem](https://semiconductor.samsung.com/emea/processor/modem/) instead.

Nowadays the baseband IC is most of the time integrated into the Exynos SOC directly. For special configs, standalone baseband ICs are still sold. User of the stand alone solution are i.e. automotive or IoT vendors.

Historically the Shannon baseband was at least developed since 2005. During the early days it went under the name of CMC. The CMC220 was the first LTE version of the IC which launched in 2011, shortly after the first Exynos processor. Samsung is still celebrating it in some of their [company presentations](https://images.samsung.com/is/content/samsung/assets/global/ir/docs/business-introduction/Samsung_Investor_Presentation_SLSI_2020_v1.pdf).

## IDA Compatibility And Installation

Tested with [IDA Pro](https://hex-rays.com/ida-pro/) 8.x (8.3 to 8.4 SP2). Might work on versions starting from 7.x using the revamped idapython API. 

Since I work on Linux the `install.sh` is a bash script. If you are using OSX or Windows you can perform the installation manually by copying the files in their respective directories to install the loader manually:

Script | Installation Directory
|---|---|
shannon_load.py | IDADIR/loaders/
shannon_postprocess.py | IDADIR/python/
shannon_pal_reconstructor.py | IDADIR/python/
shannon_mpu.py | IDADIR/python/
shannon_scatterload.py | IDADIR/python/
shannon_generic.py | IDADIR/python/
shannon_structs.py | IDADIR/python/
shannon_names.py | IDADIR/python/
shannon_debug_traces.py | IDADIR/python/

## Bugs

This code is WIP and should be used as such. If you encounter a modem image not proper processed, please fill a bug report so I can fix the loader for it. Make sure to note the exact version of the modem image you are tryign to process so I can locate the file.

## Motivation 

I took a Shannon related tranings and had to work with Ghidra. After working with IDA for 20 years I feel much more comfortable using it compared to the dragon engine. So I started the work on this loader before another Shannon centric training this year. Doing things from scratch allowed me to get much more into the details of each and every aspect. The loader as it is resembles my idea of how I want it to work and which features I think are needed to do proper research on the bianary.

### Highly Recommended Trainings

For those of you who want to get more into baseband topics I can highly recommend the following trainings. Since these were conference trainings they are not regularly repeated classes. Keep an eye open they are happening again.

* https://hardwear.io/netherlands-2022/training/reverse-engineering-emulation-dynamic-testing-cellular-baseband-firmware.php
* https://www.offensivecon.org/trainings/2024/exploiting-basebands-and-application-processors.html

## Noteable Works 

Some Links to notable work related to the Shannon baseband:

| Name | URL |
|---|---|
KAIST BaseSpec  | https://github.com/SysSec-KAIST/BaseSpec
Comsecuris ShannonRE | https://github.com/Comsecuris/shannonRE
Hernandez Shannon Ghidra Scripts |https://github.com/grant-h/ShannonBaseband
FirmWire | https://github.com/FirmWire/FirmWire

## License

MIT License, have fun.