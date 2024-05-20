# Simple Shannon Baseband Loader for IDA Pro 8.x

This is a simple firmware loader plugin to load Samsung Exynos "Shannon" modem images in IDA Pro 8.x. This loader is designed to be lean and easy to understand. It should work with most Samsung Exynos modem images containing a TOC header. These can be found e.g. in updates for Exynos based phones. The typical file name is `modem.bin`. Sometimes the images are compressed using lz4, uncompress them before loading using lz4 utility present on most Linux distros. 

# About Samsung Shannon 

Shannon is an IC series by Samsung LSI. Most noteable product in the series is the Shannon baseband processor. Shannon is the name of a range of ICs and not the name of the modem itself. You might find other Shannon ICs made by Samsung. A typical set of Shannon ICs consists of a baseband, RF transciever, powermanagement and envelope tracking IC. All of them have different part numbers. E.g. Shannon baseband is 5300, the RF transciever is 5510, PMIC is 5200 and so on. So don't get confused, these are all different parts. You won't find much about Shannon on Samsungs website, they refer to the baseband as Exynos Modem instead.

Nowadays the baseband IC is most of the time integrated into the Exynos SOC directly. For special configs, standalone baseband ICs are still sold.

Historically the Shannon baseband was at least developed since 2005. During the early days it went under the name of CMC. The CMC220 was the first LTE version of the IC which launched in 2011, shortly after the first Exynos processor. Samsung is still celebrating it in some of their shareholder presentations.

# How To Use

The TOC header is a simple structure the loader will read to create a database of the file with proper aligned segments and entry points. For more insights just look at the code of this loader. 

To use the loader simply install it inside your IDA Pro's loader folder and the post processor into the python folder like this:

Example:
```
cp -v shannon_load.py ~/idapro-8.4/loaders/
cp -v shannon_postprocess.py ~/idapro-8.4/loaders/
```

Once installed open a `modem.bin` in IDA Pro, the loader should detect the TOC format and load the image accordingly. The postprocessor script will add additional segment information after the initial analysis has finished. Adding the segments right from the start will confuse and slow down the analysis process.

The postprocessing module does most of the magic and it will take a bit to run, please be patient.

## IDA Compatibility And Installation

Tested with IDA Pro 8.3 and 8.4.

## License

MIT License, have fun.