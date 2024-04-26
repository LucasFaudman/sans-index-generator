# sans-index-generator
Generate Indexes from SANS PDFs
```bash
usage: extractpdfs.py [-h] [-P PASSWORD] [-O OUT] [--maxwidth MAXWIDTH]
                      [--only-page-order] [--only-alpha]
                      [--keep-roadmap | --no-keep-roadmap]
                      [--keep-toc | --no-keep-toc]
                      [--keep-continuation | --no-keep-continuation]
                      [--keep-summary | --no-keep-summary]
                      [--keep-labs | --no-keep-labs] [--load-index LOAD_INDEX]
                      [--save-index SAVE_INDEX]
                      [FILENAMES ...]

Extracts indexes from SANS PDF files.

positional arguments:
  FILENAMES             the PDF files to unlock and extract indexes from

optional arguments:
  -h, --help            show this help message and exit
  -P PASSWORD, --password PASSWORD
                        the password to unlock the PDF files
  -O OUT, --out OUT     Output file
  --maxwidth MAXWIDTH   Maximum width of output
  --only-page-order     Print index only in page order
  --only-alpha          Print index only in alphabetical order
  --keep-roadmap, --no-keep-roadmap
                        Keep roadmap
  --keep-toc, --no-keep-toc
                        Keep table of contents
  --keep-continuation, --no-keep-continuation
                        Keep continuation
  --keep-summary, --no-keep-summary
                        Keep summary
  --keep-labs, --no-keep-labs
                        Keep labs
  --load-index LOAD_INDEX
                        Load index from file
  --save-index SAVE_INDEX
                        Save index to file
```