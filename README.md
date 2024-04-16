# Simple Shannon Baseband Loader for IDA Pro 8.x

This is a simple firmware loader plugin to load Samsung Shannon modem images in IDA Pro 8.x. Shannon is an IC series by Samsung LSI, most noteable is the Shannon Baseband processor. Shannon ICs are used in all Samsung Exynos based phones on the market.

This loader is designed to be lean and easy to understand. It should work with most Samsung Shannon modem images containing a TOC header. These can be found in most updates for exynos based phones, the typical file name is modem.bin. Sometimes the images are compressed using lz4, uncompress them before loading using lz4 utility present on most Linux distros. 

# How To Use

The TOC header is a simple structure the loader will read to create a database of the file with proper aligned segments and entry points. For more insights just look at the code of this loader. 

To use the loader simply install it inside your IDA Pro's loader folder and the post processor into the python folder like this:

Example:
```
cp -v shannon_load.py ~/idapro-8.4/loaders/
cp -v shannon_postprocess.py ~/idapro-8.4/loaders/
```

Once installed open a `modem.bin` in IDA Pro, the loader should detect the TOC format and load the image accordingly. The postprocessor script will add additional segment information after the initial analysis has finished. Adding the segments right from the start will confuse and slow down the analysis process.

## IDA Compatibility And Installation

Tested with IDA Pro 8.3 and 8.4.

## License

MIT License, have fun.