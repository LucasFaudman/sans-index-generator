import argparse
import re
import json
from sys import stdout, stderr
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor

from textwrap import TextWrapper
from PyPDF2 import PdfReader


def fix_text(text):
    text = re.sub(r"\b([TY])\s", r"\1", text)
    text = re.sub(r'[\t ]+', ' ', text)
    text = text.replace('Secu rity', 'Security')
    text = text.strip()
    return text

def extract_pdf_text(filename, password=None):
    pages = {}
    pdf = PdfReader(Path(filename), password=password)
    pdf._flatten()

    cover, terms_page = list(pdf.pages)[0:2]
    cover_lines = cover.extract_text().split('\n')
    course_title = cover_lines.pop(0).split('sans.org')[1].replace(' & ', ' and ')
    while not (next_line := cover_lines.pop(0)).startswith('GIAC'):
        course_title += ' ' + next_line
    course_title = fix_text(course_title)

    course_code, course_name = course_title.split(' | ', 1)
    authors = terms_page.extract_text().split('.')[0]

    header = ''
    last_header = ''
    for n, page in enumerate(pdf.flattened_pages[2:]):
        page_num = n+1

        text = page.extract_text()
        text = text.split(authors)[0]
        text = fix_text(text)
        references = re.search(
            r'References:\n?(?:\[\d+\].+\n?)+', text, flags=re.MULTILINE)
        if references:
            references = references.group(0)
            text = text.replace(references, '')

        lines = text.split('\n')
        end_of_slide_pattern = rf"{course_code} \| +{course_name}\s?"

        if re.search(r"TABLE\sOF\sCONTENTS", lines[0], flags=re.IGNORECASE):
            header = "TABLE OF CONTENTS"

        elif re.search(r"Course Roadmap", text, flags=re.IGNORECASE):
            header = "Course Roadmap"

        elif re.search(end_of_slide_pattern, text, flags=re.IGNORECASE):
            text = re.split(end_of_slide_pattern, text,
                            flags=re.IGNORECASE | re.MULTILINE)[1]
            text = re.sub(r"[••–].+", '',
                          text).replace(str(page_num), '').strip()
            text = re.sub(r"^[^A-Z].+", '',
                          text).replace(str(page_num), '').strip()
            header = text.splitlines()[0] if text else ''

        if last_header == header:
            header = last_header + \
                (' (CONT)' if not last_header.endswith('(CONT)') else '')

        if not header:
            header = f'UNKNOWN HEADER - {lines[0]}'

        header = fix_text(header)
        pages[page_num] = (header, text, references)
        print(f"Read {filename} Page {page_num}: {header}", file=stderr)
        last_header = header
        header = ''

    return filename, pages


def make_index(file_pages, keep_roadmap=False, keep_toc=False, keep_continuation=False, keep_summary=False, keep_labs=False):
    index = defaultdict(dict)
    for filename, pages in file_pages.items():
        for page_num, (header, text, references) in pages.items():
            if not keep_roadmap and header.startswith(("Course Roadmap", "Course Outline")):
                continue
            if not keep_toc and header == "TABLE OF CONTENTS":
                continue
            if not keep_continuation and header.endswith('(CONT)'):
                continue
            if not keep_summary and header.startswith('Summary') or header.startswith('Module Summary'):
                continue
            if not keep_labs and header.startswith('Lab') or header.startswith('Please work on'):
                continue

            index[filename][page_num] = header

    return index


def print_index_by_page_order(index, stream=None, maxwidth=80):
    for filename, pages in index.items():
        print(f"{filename}:\n", file=stream)
        max_pagenum_strlen = len(str(max(pages.keys())))
        for page_num, header in pages.items():
            pagestr = str(page_num).ljust(max_pagenum_strlen) + ": "
            pagestr_len = len(pagestr)
            wrapper = TextWrapper(
                width=maxwidth, initial_indent=pagestr, subsequent_indent=' '*pagestr_len)
            print('\n'.join(wrapper.wrap(header)), file=stream)
        print("\n", file=stream)


def print_index_by_alpha_order(index, stream=None, maxwidth=80):
    filenums = {filename: n+1 for n, filename in enumerate(index.keys())}
    alpha_index = defaultdict(list)

    for filename, pages in index.items():
        for page_num, header in pages.items():
            alpha_index[header].append(f"{filenums[filename]}:{page_num}")

    def sort_fn(x): return x[0].replace(
        'The ', '', 1).replace('A ', '', 1).lower()
    alpha_index = dict(sorted(alpha_index.items(), key=sort_fn))
    max_pagestr_len = max(len(": " + ','.join(page_nums))
                          for page_nums in alpha_index.values())

    for header, page_nums in alpha_index.items():
        pagestr = ": " + ','.join(page_nums).ljust(max_pagestr_len)

        max_header_witdh = max(maxwidth - len(pagestr), 20)
        wrapper = TextWrapper(width=max_header_witdh)
        wrapped_header = wrapper.wrap(header)
        for i, line in enumerate(wrapped_header):
            if i == 0:
                print(f"{line.ljust(max_header_witdh)}{pagestr}", file=stream)
            else:
                print(line.ljust(maxwidth), file=stream)


def main():
    parser = argparse.ArgumentParser(
        description='Extracts indexes from SANS PDF files.')
    parser.add_argument('FILENAMES', metavar='FILENAMES', type=str, nargs='*', default=[],
                        help='the PDF files to unlock and extract indexes from')
    parser.add_argument("-P", '--password', dest='PASSWORD', required=False, type=str, default=None,
                        help='the password to unlock the PDF files')

    parser.add_argument('-O', '--out', type=str,
                        default=None, help='Output file')
    parser.add_argument('--maxwidth', type=int, default=120,
                        help='Maximum width of output')
    parser.add_argument('--only-page-order',
                        action='store_true', help='Print index only in page order')
    parser.add_argument('--only-alpha', action='store_true',
                        help='Print index only in alphabetical order')

    parser.add_argument(
        '--keep-roadmap', action=argparse.BooleanOptionalAction, help='Keep roadmap')
    parser.add_argument(
        '--keep-toc', action=argparse.BooleanOptionalAction, help='Keep table of contents')
    parser.add_argument('--keep-continuation',
                        action=argparse.BooleanOptionalAction, help='Keep continuation')
    parser.add_argument(
        '--keep-summary', action=argparse.BooleanOptionalAction, help='Keep summary')
    parser.add_argument(
        '--keep-labs', action=argparse.BooleanOptionalAction, help='Keep labs')

    parser.add_argument('--load-index', type=str,
                        default=None, help='Load index from file')
    parser.add_argument('--save-index', type=str,
                        default=None, help='Save index to file')

    args = parser.parse_args()

    if not args.FILENAMES and not args.load_index:
        parser.error("No PDF files specified")

    if args.only_page_order and args.only_alpha:
        parser.error("Cannot use both --only-page-order and --only-alpha")

    if not args.load_index:
        num_files = len(args.FILENAMES)
        with ProcessPoolExecutor() as executor:
            print(f"Extracting text from {num_files} files...", file=stderr)
            file_pages = dict(executor.map(extract_pdf_text,
                              args.FILENAMES, [args.PASSWORD]*num_files))
            print(f"\nDone extracting text {num_files} files.\n", file=stderr)

        index = make_index(file_pages,
                           args.keep_roadmap,
                           args.keep_toc,
                           args.keep_continuation,
                           args.keep_summary,
                           args.keep_labs)

        if args.save_index:
            with open(args.save_index, 'w') as f:
                json.dump(index, f, indent=4)

    else:
        with open(args.load_index, 'r') as f:
            index = json.load(f)

    stream = open(args.out, 'w+') if args.out else stdout
    if not args.only_alpha:
        print_index_by_page_order(index, stream, args.maxwidth)
    if not args.only_page_order:
        print_index_by_alpha_order(index, stream, args.maxwidth)

    stream.close()


if __name__ == "__main__":
    main()
