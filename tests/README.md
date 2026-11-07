# Tests

These tests use the app the way a person does, with real mouse clicks, key presses, page refreshes and file downloads in a hidden copy of Google Chrome. They don't change the app or your CSV files.

## Running them

You need Python 3 and Google Chrome, and nothing else needs installing. From the project folder, run:

```
python3 tests/run_tests.py
```

It takes about a minute. The last lines say how many checks passed and list any that failed.

| Option | What it does |
|---|---|
| `--only tracing` | Runs only the sections whose name contains that word |
| `--app path/to/copy.html` | Tests a different copy of the app |

Run the tests after every change to the app. If one fails, either the change broke something or a behaviour changed on purpose, in which case update the test to match.

If a section says `stopped early` with `Broken pipe` or `Connection reset`, the connection to Chrome dropped, rather than a check failing. Run the tests again. This happened once and couldn't be reproduced, so if it keeps happening, the cause still needs finding.

## What's covered

| Section | What it checks |
|---|---|
| `start_screen` | The blue start screen and when it goes away |
| `self_contained` | Nothing is loaded from the internet |
| `csv_format` | Quotes, commas and line breaks survive saving and reloading |
| `file_checks` | Every kind of bad file is rejected with a clear message |
| `layout`, `entry_points` | No lines through boxes or on top of each other, and parents enter on the correct side |
| `text_fitting` | Text at your size limits fits, and nothing is cut off |
| `duplicates` | Duplicate colours and leaf numbers, on screen and in exports |
| `tracing` | Every node's trace, compared with a separate version of the rules written in Python |
| `mouse_and_keyboard` | Click, double-click, drag, pan, snapping and Esc |
| `splitting`, `undo_split` | Tabs, page links, blocked splits, nested splits and undo |
| `undo_and_redo` | Ctrl+Z and redo for drags, Auto-Arrange, splits and Undo Split |
| `unsaved_warnings` | The unsaved message, the replace prompt and the browser's leave warning |
| `saving_and_refresh` | Refresh, Save CSV, older split files and damaged saved data |
| `print_sizes` | One shared text size, fitting on Letter portrait, and warnings |
| `exports` | Real SVG and PNG downloads and what they contain |
| `export_labels`, `named_font` | The identifying line on exports, and the font in use |
| `help_panel` | Opening, closing and scrolling Help |
| `window_sizes` | Toolbar and Fit All at laptop and small window sizes |

## What isn't covered

- Microsoft Word and real printing
- Safari, Firefox and Edge
- Your browser's prompt for allowing several downloads

Check these by hand before relying on a diagram in a document.

## Sample files

The tests use their own copies in `fixtures/`, so editing `config.csv` can't break them:

| File | Purpose |
|---|---|
| `sample_tree.csv` | A 24-node tree with shared children and duplicates |
| `dense_dag.csv` | A 13-node diagram with many shared children |
| `text_limits.csv` | Text at and beyond the size limits |
