#!/usr/bin/env python3
"""Tests for threat_tree_diagrammer.html, using real mouse and keyboard input in headless Chrome.

Run:      python3 tests/run_tests.py
Options:  --app PATH     test a different copy of the HTML file
          --only WORD    run only the sections whose name contains WORD

Needs Python 3 and Google Chrome, and nothing else. See tests/README.md.
"""
import argparse
import base64
import csv
import io
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_APP = os.path.join(HERE, '..', 'threat_tree_diagrammer.html')
CHROME_PATHS = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
]
HEADER = 'ID,Parent_ID,Type,Title,Description,Potentiality,X,Y\n'


def fixture(name):
    with open(os.path.join(HERE, 'fixtures', name), encoding='utf-8') as f:
        return f.read()


SAMPLE = fixture('sample_tree.csv')
DENSE = fixture('dense_dag.csv')
LIMITS = fixture('text_limits.csv')


# --- A small client for Chrome's debugging protocol, using only the standard library ---

class Browser:
    def __init__(self, download_dir):
        chrome = next((p for p in CHROME_PATHS if os.path.exists(p)), None)
        if not chrome:
            sys.exit('Google Chrome was not found. Add its location to CHROME_PATHS in this file.')
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.profile = tempfile.mkdtemp(prefix='threat_tree_chrome_')
        self.process = subprocess.Popen(
            [chrome, '--headless=new', '--disable-gpu', '--no-first-run', f'--user-data-dir={self.profile}',
             f'--remote-debugging-port={self.port}', '--window-size=1500,1000', 'about:blank'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                pages = [t for t in self.targets() if t['type'] == 'page']
                if pages:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            self.close()
            sys.exit('Chrome did not start.')
        self.tab = Tab(pages[0]['webSocketDebuggerUrl'])
        self.tab.call('Browser.setDownloadBehavior', behavior='allow', downloadPath=download_dir)

    def targets(self):
        return json.load(urllib.request.urlopen(f'http://127.0.0.1:{self.port}/json'))

    def new_tab(self, url):
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}/json/new?{url}', method='PUT')
        target = json.load(urllib.request.urlopen(request))
        tab = Tab(target['webSocketDebuggerUrl'])
        tab.target_id = target['id']
        return tab

    def close_tab(self, tab):
        tab.sock.close()
        urllib.request.urlopen(f'http://127.0.0.1:{self.port}/json/close/{tab.target_id}').read()
        self.tab.call('Page.bringToFront')  # A tab left in the background runs slowly

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


class Tab:
    def __init__(self, url):
        host = url.split('/')[2]
        path = '/' + url.split('/', 3)[3]
        hostname, port = host.split(':')
        self.sock = socket.create_connection((hostname, int(port)))
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                           f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        reply = b''
        while b'\r\n\r\n' not in reply:
            reply += self.sock.recv(1)
        self.next_id = 0
        self.dialogs = []
        self.call('Page.enable')
        self.call('Runtime.enable')

    def _send(self, message):
        data = json.dumps(message).encode()
        mask = os.urandom(4)
        n = len(data)
        if n < 126:
            head = bytes([0x81, 0x80 | n])
        elif n < 65536:
            head = bytes([0x81, 0x80 | 126]) + struct.pack('>H', n)
        else:
            head = bytes([0x81, 0x80 | 127]) + struct.pack('>Q', n)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _read(self, n):
        data = b''
        while len(data) < n:
            data += self.sock.recv(n - len(data))
        return data

    def _receive(self):
        data = b''
        while True:
            first, second = self._read(2)
            n = second & 127
            if n == 126:
                n = struct.unpack('>H', self._read(2))[0]
            elif n == 127:
                n = struct.unpack('>Q', self._read(8))[0]
            data += self._read(n)
            if first & 0x80:
                return data

    def call(self, method, **params):
        self.next_id += 1
        wanted = self.next_id
        self._send({'id': wanted, 'method': method, 'params': params})
        while True:
            reply = json.loads(self._receive())
            if reply.get('method') == 'Page.javascriptDialogOpening':
                self.dialogs.append(reply['params']['type'])
                self.next_id += 1
                self._send({'id': self.next_id, 'method': 'Page.handleJavaScriptDialog', 'params': {'accept': True}})
                continue
            if reply.get('id') == wanted:
                if 'error' in reply:
                    raise RuntimeError(reply['error'])
                return reply['result']

    def ev(self, expression):
        """Runs JavaScript in the page and returns its value."""
        result = self.call('Runtime.evaluate', expression=expression, returnByValue=True, awaitPromise=True)
        if 'exceptionDetails' in result:
            details = result['exceptionDetails']
            raise RuntimeError(details.get('exception', {}).get('description') or details.get('text'))
        return result['result'].get('value')

    def js(self, expression):
        """Runs JavaScript returning a value too rich to pass directly, via JSON."""
        return json.loads(self.ev(f'JSON.stringify({expression})'))


# --- Test harness ---

class Results:
    def __init__(self):
        self.passed = 0
        self.failures = []
        self.section = ''

    def check(self, name, condition, detail=None):
        if condition:
            self.passed += 1
        else:
            self.failures.append(f'{self.section}: {name}' + (f'  ->  {detail}' if detail is not None else ''))
            print(f'  FAIL {name}' + (f'  ->  {detail}' if detail is not None else ''))

    def equal(self, name, actual, expected):
        self.check(name, actual == expected, f'got {actual!r}, expected {expected!r}')


SECTIONS = []


def section(function):
    SECTIONS.append(function)
    return function


class Driver:
    """Everything a test needs to use the app the way a person does."""

    def __init__(self, tab, app_url, results, download_dir):
        self.tab = tab
        self.app_url = app_url
        self.r = results
        self.downloads = download_dir
        self.ev = tab.ev
        self.js = tab.js

    def fresh(self):
        """Opens the app at its start screen, with no saved session."""
        self.tab.call('Page.navigate', url=self.app_url)
        time.sleep(0.3)
        self.ev("window.removeEventListener('pagehide', saveSession); sessionStorage.clear()")
        self.reload()

    def reload(self):
        self.tab.call('Page.reload')
        time.sleep(0.4)

    def load(self, text, dismiss=True):
        """Loads a CSV through the app's real file-loading path."""
        self.ev(f"""new Promise(r => {{
            processFile(new File([{json.dumps(text)}], 'test.csv'));
            if (hasUnsavedChanges) document.getElementById('confirmYes').click();
            setTimeout(r, 200);
        }})""")
        if dismiss:
            self.dismiss()

    def dismiss(self):
        self.ev("document.getElementById('customAlertModal').classList.add('hidden')")

    def notice(self):
        return self.ev("getComputedStyle(document.getElementById('customAlertModal')).display !== 'none'"
                       " ? document.getElementById('customAlertMessage').innerText : null")

    def load_error(self, text):
        """The error a CSV produces, or None if it's accepted."""
        return self.ev(f"(() => {{ try {{ buildTreeFromCSV(parseCSV({json.dumps(text)})); return null; }}"
                       f" catch (e) {{ return e.message; }} }})()")

    # Real input
    def mouse(self, kind, x, y, count=0):
        self.tab.call('Input.dispatchMouseEvent', type=kind, x=x, y=y,
                      button='none' if kind == 'mouseMoved' else 'left', clickCount=count)

    def click_at(self, x, y):
        self.mouse('mouseMoved', x, y)
        self.mouse('mousePressed', x, y, 1)
        self.mouse('mouseReleased', x, y, 1)
        time.sleep(0.55)  # Longer than a double-click, so the next click stands alone

    def double_click_at(self, x, y, wobble=0):
        self.mouse('mouseMoved', x, y)
        self.mouse('mousePressed', x, y, 1)
        self.mouse('mouseReleased', x, y, 1)
        if wobble:
            self.mouse('mouseMoved', x + wobble, y)
        self.mouse('mousePressed', x + wobble, y, 2)
        self.mouse('mouseReleased', x + wobble, y, 2)
        time.sleep(0.55)

    def drag(self, x, y, dx, dy, steps=6):
        self.mouse('mouseMoved', x, y)
        self.mouse('mousePressed', x, y, 1)
        for i in range(1, steps + 1):
            self.mouse('mouseMoved', x + dx * i / steps, y + dy * i / steps)
        self.mouse('mouseReleased', x + dx, y + dy, 1)
        time.sleep(0.1)

    def press_escape(self):
        for kind in ('keyDown', 'keyUp'):
            self.tab.call('Input.dispatchKeyEvent', type=kind, key='Escape', code='Escape', windowsVirtualKeyCode=27)

    def press_undo(self, redo=False):
        modifiers = 4 | (8 if redo else 0)  # Meta, plus Shift for redo
        for kind in ('keyDown', 'keyUp'):
            self.tab.call('Input.dispatchKeyEvent', type=kind, key='z', code='KeyZ', windowsVirtualKeyCode=90, modifiers=modifiers)
        time.sleep(0.05)

    def node_point(self, node_id):
        """Screen position just inside a node's description box."""
        return self.js(f"""(() => {{
            const n = nodesArray.find(n => n.id === {json.dumps(node_id)});
            const m = svg.querySelector('g').getScreenCTM();
            return [n.x * m.a + m.e, (n.y + 20) * m.d + m.f];
        }})()""")

    def click_node(self, node_id):
        self.click_at(*self.node_point(node_id))

    def button(self, label):
        point = self.js(f"""(() => {{
            const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === {json.dumps(label)});
            const r = b.getBoundingClientRect();
            return [r.x + r.width / 2, r.y + r.height / 2];
        }})()""")
        self.mouse('mouseMoved', *point)
        self.mouse('mousePressed', *point, 1)
        self.mouse('mouseReleased', *point, 1)
        time.sleep(0.1)

    def tabs(self):
        return self.js("[...document.querySelectorAll('.page-tab')].map(t => t.textContent)")

    def split(self, *ids):
        """Splits at each node, choosing it from the Master tab."""
        for node_id in ids:
            self.ev(f"goToPage(0); setTracedNode(allNodes.find(n => n.id === {json.dumps(node_id)})); splitSelectedNode()")

    def arrange_pages(self):
        self.ev("pageNumbers().forEach(p => { goToPage(p); autoArrange(false); }); refreshPrintSizes(); goToPage(0)")

    def modal_open(self):
        return self.ev("!document.getElementById('infoModal').classList.contains('hidden')")

    def help_open(self):
        return self.ev("!document.getElementById('helpModal').classList.contains('hidden')")

    def highlighted(self, kind):
        return self.js(f"renderedElements.nodes.filter(o => o.el.classList.contains('{kind}')).map(o => o.node.id)")

    def audit_layout(self):
        """Looks for lines through boxes, lines running on top of each other, overlapping nodes and crossings."""
        return self.js("""(() => {
            const { paths, edges } = computeConnectors();
            const segments = [];
            paths.forEach((points, index) => {
                for (let i = 0; i < points.length - 1; i++) segments.push({ index, a: points[i], b: points[i + 1] });
            });
            const low = (s, k) => Math.min(s.a[k], s.b[k]);
            const high = (s, k) => Math.max(s.a[k], s.b[k]);
            const boxHits = [], overlapping = [];
            let crossings = 0, diagonal = 0;
            segments.forEach(s => {
                if (s.a[0] !== s.b[0] && s.a[1] !== s.b[1]) diagonal++;
                const e = edges[s.index];
                nodesArray.forEach(n => {
                    if (n === e.parent || n === e.child) return;
                    if (high(s, 0) > n.x - DESC_W / 2 && low(s, 0) < n.x + DESC_W / 2 && high(s, 1) > n.y && low(s, 1) < nodeBottom(n)) {
                        boxHits.push(e.parent.id + '>' + e.child.id + ' hits ' + n.id);
                    }
                });
            });
            segments.forEach((A, i) => segments.slice(i + 1).forEach(B => {
                const ea = edges[A.index], eb = edges[B.index];
                if (A.index === B.index || ea.parent === eb.parent) return;
                const aVertical = A.a[0] === A.b[0], bVertical = B.a[0] === B.b[0];
                if (aVertical === bVertical) {
                    const k = aVertical ? 0 : 1, o = aVertical ? 1 : 0;
                    if (A.a[k] === B.a[k] && Math.min(high(A, o), high(B, o)) - Math.max(low(A, o), low(B, o)) > 0.01) {
                        overlapping.push(ea.parent.id + '>' + ea.child.id + ' on ' + eb.parent.id + '>' + eb.child.id);
                    }
                } else {
                    const V = aVertical ? A : B, H = aVertical ? B : A;
                    if (V.a[0] > low(H, 0) && V.a[0] < high(H, 0) && H.a[1] > low(V, 1) && H.a[1] < high(V, 1)) crossings++;
                }
            }));
            return { boxHits, overlapping, crossings, diagonal, nodeOverlap: (findOverlappingNodes() || []).map(n => n.id) };
        })()""")

    def page_export_info(self):
        """Measures each tab's exported SVG and whether anything falls outside it."""
        rows = []
        for page in self.js('allTabs()'):
            self.ev(f'goToPage({page})')
            info = self.js(r"""(() => {
                const d = getSvgData();
                const svgTag = d.xml.match(/width="([\d.]+)pt" height="([\d.]+)pt"/);
                const move = d.xml.match(/translate\(([-\d.e]+),\s*([-\d.e]+)\)/);
                const box = svg.querySelector('g').getBBox();
                const left = box.x + +move[1], top = box.y + +move[2];
                return {
                    name: pageName(currentPage), widthPt: +svgTag[1], heightPt: +svgTag[2], w: d.w, h: d.h,
                    clearLeft: left, clearTop: top, clearRight: d.w - left - box.width, clearBottom: d.h - top - box.height,
                    size: tabPrintSize(currentPage)
                };
            })()""")
            info['textPt'] = 11 * info['widthPt'] / info['w']
            rows.append(info)
        return rows


# Independent versions of the app's rules, so a mistake in the app can't hide in its own logic.

class Rules:
    def __init__(self, text):
        self.kids, self.parents, self.types = {}, {}, {}
        for row in csv.DictReader(io.StringIO(text)):
            node = row['ID']
            self.types[node] = row['Type'].upper()
            self.parents[node] = [p.strip() for p in row['Parent_ID'].split(',') if p.strip()]
            for parent in self.parents[node]:
                self.kids.setdefault(parent, []).append(node)

    def trace(self, start):
        path, path_edges, branch, branch_edges, stack = set(), set(), set(), set(), [start]
        while stack:
            node = stack.pop()
            if node in path:
                continue
            path.add(node)
            for parent in self.parents[node]:
                path_edges.add((parent, node))
                if self.types[parent] == 'AND':
                    for sibling in self.kids[parent]:
                        if sibling != node:
                            branch.add(sibling)
                            branch_edges.add((parent, sibling))
                stack.append(parent)
        return path, path_edges, branch - path, branch_edges - path_edges

    def below(self, node):
        found, stack = set(), list(self.kids.get(node, []))
        while stack:
            child = stack.pop()
            if child not in found:
                found.add(child)
                stack += self.kids.get(child, [])
        return found

    def can_split(self, node):
        below = self.below(node)
        if not below or len(below) == len(self.types) - 1:
            return False
        return all(p == node or p in below for moved in below for p in self.parents[moved])


# --- Tests ---

@section
def start_screen(d, r):
    d.fresh()
    r.check('start screen shows', d.ev("getComputedStyle(document.getElementById('dropOverlay')).display") != 'none')
    r.check('no tabs yet', d.ev("document.getElementById('pageTabs').classList.contains('hidden')"))
    d.load('a,b\n', dismiss=False)
    r.check('invalid file keeps start screen', d.ev("getComputedStyle(document.getElementById('dropOverlay')).display") != 'none')
    d.dismiss()
    d.load(SAMPLE)
    r.check('valid file hides start screen', d.ev("getComputedStyle(document.getElementById('dropOverlay')).display") == 'none')
    r.equal('only Master tab before a split', d.tabs(), ['Master'])


@section
def self_contained(d, r):
    with open(d.app_url[len('file://'):], encoding='utf-8') as f:
        source = f.read()
    urls = set(re.findall(r'https?://[^\s"\'<>`]+', source))
    r.check('no outside addresses besides the SVG namespace', urls <= {'http://www.w3.org/2000/svg'}, urls)
    r.check('no external scripts or stylesheets', not re.search(r'<(script[^>]+src|link)\b', source))
    d.fresh()
    d.load(SAMPLE)
    r.equal('no network requests', d.ev("performance.getEntriesByType('resource').length"), 0)


@section
def csv_format(d, r):
    d.fresh()
    fields = '"Ti""tle, x"', '"He said ""hi"", ok\nline two"', '"pIV,pV"'
    d.load(HEADER + f'a,,OR,{fields[0]},{fields[1]},{fields[2]},-217.5,0\nb,a,BASIC,Say "x",plain,,72.5,160\n')
    node = d.js("(({title, description, potentiality}) => ({title, description, potentiality}))(allNodes[0])")
    r.equal('quotes and commas in title', node['title'], 'Ti"tle, x')
    r.equal('line break in description', node['description'], 'He said "hi", ok\nline two')
    r.equal('comma in potentiality', node['potentiality'], 'pIV,pV')
    r.equal('quote inside an unquoted field', d.ev('allNodes[1].title'), 'Say "x"')
    saved = d.ev('buildCSVText()')
    d.ev('allNodes[0].title = "changed"')  # So a failed reload can't look like a success
    d.load(saved, dismiss=False)
    r.equal('saved file loads without complaint', d.notice(), None)
    d.dismiss()
    r.equal('reloaded title is intact', d.ev('allNodes[0].title'), 'Ti"tle, x')
    r.equal('reloaded description is intact', d.ev('allNodes[0].description'), 'He said "hi", ok\nline two')
    r.equal('save and reload is identical', d.ev('buildCSVText()'), saved)
    r.check('half units survive saving', ',-217.5,0' in saved, saved)
    r.equal('Windows line endings', len(d.js(f"parseCSV({json.dumps(HEADER.replace(chr(10), chr(13) + chr(10)) + 'a,,BASIC,T,D,,0,0' + chr(13) + chr(10))})")), 1)
    r.equal('no final line break', d.js(f"parseCSV({json.dumps(HEADER + 'a,,BASIC,T,D,,1,2')})[0].y"), '2')


@section
def file_checks(d, r):
    d.fresh()
    cases = {
        'duplicate ID': (HEADER + 'a,,BASIC,A,A,,,\na,,BASIC,B,B,,,\n', 'Duplicate ID'),
        'row without ID': (HEADER + ',,BASIC,Lost,Text,,,\n', 'has no ID'),
        '4 parents': (HEADER + 'a,,OR,A,A,,,\nb,,OR,B,B,,,\nc,,OR,C,C,,,\nd,,OR,D,D,,,\ne,"a,b,c,d",BASIC,E,E,,,\n', '4 parents'),
        'repeated parent': (HEADER + 'r,,OR,R,R,,,\nc,"r,r",BASIC,C,C,,,\n', 'same parent'),
        'missing parent': (HEADER + 'a,,OR,A,A,,,\nb,"a,nope",BASIC,B,B,,,\n', "doesn't exist"),
        'cycle': (HEADER + 'r,,OR,R,R,,,\nx,"r,y",OR,X,X,,,\ny,x,OR,Y,Y,,,\n', 'Circular'),
        'own parent': (HEADER + 'r,,OR,R,R,,,\nx,"r,x",OR,X,X,,,\n', 'Circular'),
        'unsupported type': (HEADER + 'a,,XOR,A,A,,,\nb,a,BASIC,B,B,,,\n', 'unsupported Type'),
        'blank type': (HEADER + 'a,,,A,A,,,\n', 'unsupported Type'),
        'BASIC with children': (HEADER + 'a,,BASIC,A,A,,,\nb,a,BASIC,B,B,,,\n', 'BASIC but has children'),
        'unquoted parent list': (HEADER + 'a,,OR,A,A,,,\nb,,OR,B,B,,,\nc,a,b,BASIC,C,C,,,\n', 'more columns'),
        'unclosed quote': (HEADER + 'a,,BASIC,"oops,D,,0,0\n', 'never closed'),
    }
    for name, (text, expected) in cases.items():
        error = d.load_error(text)
        r.check(name, error is not None and expected in error, error)
    pages = 'ID,Parent_ID,Type,Title,Description,Potentiality,X,Y,Page,Page_X,Page_Y,Split_Page,Split_X,Split_Y\n'
    page_cases = {
        'child on wrong page': (pages + 'a,,OR,A,A,,0,0,1,0,0,,,\nb,a,OR,B,B,,0,0,2,0,0,,,\nc,b,BASIC,C,C,,0,0,2,0,0,,,\n', 'expects it on page'),
        'invalid page': (pages + 'a,,BASIC,A,A,,0,0,x,0,0,,,\n', 'invalid Page'),
        'split on a leaf': (pages + 'a,,BASIC,A,A,,0,0,1,0,0,2,0,0\n', 'no children'),
        'two splits to one page': (pages + 'r,,AND,R,R,,0,0,1,0,0,,,\na,r,OR,A,A,,0,0,1,0,0,2,0,0\nb,r,OR,B,B,,0,0,1,0,0,2,0,0\nc,a,BASIC,C,C,,0,0,2,0,0,,,\nd,b,BASIC,D,D,,0,0,2,0,0,,,\n', 'More than one node'),
    }
    for name, (text, expected) in page_cases.items():
        error = d.load_error(text)
        r.check(name, error is not None and expected in error, error)
    r.equal('valid 3 parents accepted', d.load_error(HEADER + 'a,,OR,A,A,,,\nb,,OR,B,B,,,\nc,,OR,C,C,,,\ne,"a,b,c",BASIC,E,E,,,\n'), None)
    d.load(SAMPLE)
    d.load(HEADER + 'x,nope,BASIC,X,X,,,\n', dismiss=False)
    r.check('bad file shows a notice', 'nope' in (d.notice() or ''))
    d.dismiss()
    r.equal('bad file keeps the diagram', d.ev('allNodes.length'), 24)
    d.load(HEADER + 'r,,AND,R,R,,,\na,r,AND,A,A,,,\nb,r,BASIC,B,B,,,\n', dismiss=False)
    r.check('gate with no inputs gets a notice', '"a"' in (d.notice() or ''))
    d.dismiss()
    r.equal('gate with no inputs still drawn', d.ev("document.querySelectorAll('.gate-path').length"), 2)


@section
def layout(d, r):
    d.fresh()
    d.load(SAMPLE)
    d.ev('autoArrange()')
    audit = d.audit_layout()
    r.equal('sample: no lines through boxes', audit['boxHits'], [])
    r.equal('sample: no lines on top of each other', audit['overlapping'], [])
    r.equal('sample: no overlapping nodes', audit['nodeOverlap'], [])
    r.equal('sample: no crossings', audit['crossings'], 0)
    r.equal('sample: square corners only', audit['diagonal'], 0)
    before = d.js('allNodes.map(n => [n.x, n.y])')
    d.ev("nodesArray[1].x += 300; nodesArray[1].y += 300; autoArrange()")
    r.equal('Auto-Arrange gives the same result every time', d.js('allNodes.map(n => [n.x, n.y])'), before)
    r.check('child sits below every parent', d.ev('allNodes.every(n => n.parents.every(p => p.y < n.y))'))
    d.load(DENSE)
    d.ev('autoArrange()')
    audit = d.audit_layout()
    r.equal('dense: no lines through boxes', audit['boxHits'], [])
    r.equal('dense: no lines on top of each other', audit['overlapping'], [])
    r.check('dense: at most 2 crossings', audit['crossings'] <= 2, audit['crossings'])
    d.load(HEADER + 'A,,OR,A,A,,-800,0\nB,,OR,B,B,,-600,0\nC,,OR,C,C,,-400,0\nk,"A, B, C",BASIC,K,K,,0,400\n')
    r.equal('3 parents on one side: no crossings', d.audit_layout()['crossings'], 0)


@section
def entry_points(d, r):
    def entries():
        return d.js("""(() => {
            const child = nodesArray.find(n => n.id === 'k');
            const { paths, edges } = computeConnectors();
            return Object.fromEntries(edges.map((e, i) => [e.parent.id, paths[i][paths[i].length - 1][0] - child.x]));
        })()""")
    d.fresh()
    d.load(HEADER + 'L,,OR,L,L,,-300,0\nM,,OR,M,M,,0,0\nR,,OR,R,R,,300,0\nk,"R, L, M",BASIC,K,K,,0,400\n')
    e = entries()
    r.check('left, overhead and right parents enter accordingly', e['L'] < 0 and e['M'] == 0 and e['R'] > 0, e)
    d.load(HEADER + 'A,,OR,A,A,,-600,0\nB,,OR,B,B,,-400,0\nk,"A, B",BASIC,K,K,,0,400\n')
    e = entries()
    r.check('two left parents stay left, apart and in order', e['A'] < e['B'] < 0 and e['B'] - e['A'] >= 24, e)
    d.load(HEADER + 'A,,OR,A,A,,-300,0\nk,A,BASIC,K,K,,0,400\n')
    r.equal('single parent enters at the centre', entries()['A'], 0)


@section
def text_fitting(d, r):
    d.fresh()
    d.load(LIMITS)
    nodes = d.js("allNodes.map(n => ({id: n.id, lines: n.descLines.length, descH: n.descH, titleLines: n.titleLines.length, font: n.titleFontSize}))")
    by_id = {n['id']: n for n in nodes}
    r.check('4 full lines fit without growing the box', by_id['root']['lines'] == 4 and by_id['root']['descH'] == 69, by_id['root'])
    r.check('all boxes at the limits stay one height', {n['descH'] for n in nodes} == {69})
    r.check('long capitals title shrinks and stays on one line', by_id['root']['titleLines'] == 1 and by_id['root']['font'] < 11, by_id['root'])
    r.check('normal title keeps its size', by_id['d']['font'] == 11, by_id['d'])
    r.equal('typed line breaks are kept', d.js("allNodes.find(n => n.id === 'e').descLines"), ['Short text', 'second line'])
    long_text = 'Attacker exploits an unauthenticated maintenance interface on the gateway to load a modified configuration table during ground operations which then persists across power cycles'
    d.load(HEADER + f'a,,AND,A,"{long_text}",pIV,,\nb,a,BASIC,VERY-LONG-TITLE-THAT-DOES-NOT-FIT-IN-THE-BOX-AT-ALL,B,"Very Long Potentiality Value That Keeps Going",,\nc,a,BASIC,C,C,,,\n')
    problems = d.js("""(() => {
        const out = [];
        renderedElements.nodes.forEach(({ el, node }) => {
            const rects = [...el.querySelectorAll('rect')].map(r => r.getBBox());
            const shown = [...el.querySelectorAll('text.node-text')].map(t => t.textContent).join(' ');
            const squash = s => s.replace(/\\s+/g, '');
            if (squash(shown) !== squash(node.description + node.title)) out.push('text lost on ' + node.id);
            el.querySelectorAll('text.node-text').forEach(t => {
                const b = t.getBBox();
                if (!rects.some(r => b.x >= r.x && b.x + b.width <= r.x + r.width && b.y >= r.y - 1 && b.y + b.height <= r.y + r.height + 1)) out.push('outside box: ' + t.textContent);
            });
            const title = rects[1];
            const symbol = el.querySelector('.leaf-circle');
            el.querySelectorAll('.node-potentiality').forEach(t => {
                const b = t.getBBox();
                if (b.y < title.y + title.height - 0.5) out.push('potentiality inside box on ' + node.id);
                if (Math.abs(b.x + b.width - (title.x + title.width)) > 0.6) out.push('potentiality not at right edge on ' + node.id);
                if (symbol) {
                    const s = symbol.getBBox();
                    if (b.x < s.x + s.width && b.x + b.width > s.x && b.y < s.y + s.height && b.y + b.height > s.y) out.push('potentiality touches circle on ' + node.id);
                }
            });
        });
        return out;
    })()""")
    r.equal('no text cut off, outside its box, or colliding', problems, [])


@section
def duplicates(d, r):
    d.fresh()
    d.load(HEADER + 'r,,AND,R,R,,,\n'
           'g1,r,OR,GATE,Same gate,pI,,\ng2,r,OR,GATE,Same gate,pI,,\n'
           'a,g1,BASIC,LEAF,Same leaf,pV,,\nb,g2,BASIC,LEAF,Same leaf,pV,,\n'
           'c,g1,BASIC,Other,Text,pV,,\nd,g2,BASIC,other,Text,pV,,\n'
           'e,r,BASIC,,,,,\nf,r,BASIC,,,,,\n')
    look = d.js("""Object.fromEntries(renderedElements.nodes.map(({ el, node }) => [node.id, {
        fill: el.querySelector('rect').getAttribute('fill'),
        number: el.querySelector('.duplicate-number')?.textContent ?? null
    }]))""")
    r.equal('duplicate gates share a colour', look['g1']['fill'], look['g2']['fill'])
    r.equal('duplicate leaves share a colour', look['a']['fill'], look['b']['fill'])
    r.check('groups differ in colour', look['a']['fill'] != look['g1']['fill'])
    r.equal('duplicate leaves share a number', [look['a']['number'], look['b']['number']], ['1', '1'])
    r.equal('duplicate gates have no number', [look['g1']['number'], look['g2']['number']], [None, None])
    r.equal('capital letters count as different', look['c']['number'], None)
    r.equal('blank rows are not duplicates', look['e']['number'], None)
    xml = d.ev('getSvgData().xml')
    r.equal('export: every box is white', set(re.findall(r'<rect[^>]*?fill="([^"]+)"', xml)), {'white'})
    r.equal('export: leaf numbers kept', xml.count('duplicate-number'), 2)


@section
def tracing(d, r):
    rules = Rules(SAMPLE)
    d.fresh()
    d.load(SAMPLE)
    mismatches = []
    for node in rules.types:
        d.ev(f"setTracedNode(allNodes.find(n => n.id === {json.dumps(node)}))")
        path, path_edges, branch, branch_edges = rules.trace(node)
        state = d.js("""({
            pe: renderedElements.edges.filter(o => o.el.classList.contains('trace-edge-path')).map(o => [o.edge.parent.id, o.edge.child.id]),
            be: renderedElements.edges.filter(o => o.el.classList.contains('trace-edge-branch')).map(o => [o.edge.parent.id, o.edge.child.id])
        })""")
        if (set(d.highlighted('trace-node-path')) != path or set(d.highlighted('trace-node-branch')) != branch
                or {tuple(e) for e in state['pe']} != path_edges or {tuple(e) for e in state['be']} != branch_edges
                or set(d.highlighted('trace-dim')) != set(rules.types) - path - branch):
            mismatches.append(node)
    r.equal('every node matches the trace rules', mismatches, [])
    d.ev("setTracedNode(allNodes.find(n => n.id === '13'))")
    below = rules.below('13')
    r.check('never goes down to children', not below & set(d.highlighted('trace-node-path') + d.highlighted('trace-node-branch')))
    xml = d.ev('getSvgData().xml')
    r.check('export has no trace', not re.search(r'trace-|#dc2626|#ea580c|stroke-dasharray', xml))
    d.ev('setTracedNode(null)')
    r.equal('clearing removes all highlights', d.highlighted('trace-dim') + d.highlighted('trace-node-path'), [])


@section
def mouse_and_keyboard(d, r):
    d.fresh()
    d.load(SAMPLE)
    x, y = d.node_point('13')
    position = "[nodesArray.find(n => n.id === '13').x, nodesArray.find(n => n.id === '13').y]"
    start = d.js(position)
    d.click_at(x, y)
    r.check('single click: no Details window', not d.modal_open())
    r.equal('single click on Master traces', d.ev('tracedNode.id'), '13')
    d.double_click_at(x, y)
    r.check('double click opens Details', d.modal_open())
    r.equal('Details shows the right node', d.ev("document.getElementById('modalTitle').innerText"), '13')
    d.press_escape()
    r.check('Esc closes Details first', not d.modal_open())
    r.equal('...and keeps the trace', d.ev('tracedNode.id'), '13')
    d.press_escape()
    r.equal('Esc again clears the trace', d.ev('tracedNode'), None)
    d.double_click_at(x, y, wobble=2)
    r.check('double click with a small wobble works', d.modal_open())
    d.ev('closeModal()')
    r.equal('clicking never moves a node', d.js(position), start)
    d.drag(x, y, 2, 1, steps=2)
    r.equal('tiny press-and-release leaves the node', d.js(position), start)
    d.ev('setTracedNode(null)')
    d.drag(x, y, 90, 60)
    r.check('dragging moves the node', d.js(position) != start)
    r.check('dragging opens nothing', not d.modal_open())
    r.equal('dragging does not trace', d.ev('tracedNode'), None)
    r.equal('no leftover alignment guides', d.ev("svg.querySelectorAll('[stroke-dasharray]').length"), 0)
    d.ev('autoArrange()')
    d.click_node('22')
    d.click_at(60, 900)
    r.equal('clicking empty space clears the trace', d.ev('tracedNode'), None)
    d.click_node('22')
    d.drag(60, 900, 50, -40)
    r.equal('panning keeps the trace', d.ev('tracedNode.id'), '22')
    d.ev('setTracedNode(null)')
    d.ev('autoArrange()')
    # Snapping shows a guide during the drag and clears it afterwards
    x, y = d.node_point('20')
    gap = d.js("""(() => {
        const n = nodesArray.find(n => n.id === '20'), other = nodesArray.find(n => n.id === '4');
        return (other.x - n.x) * svg.querySelector('g').getScreenCTM().a;
    })()""")
    d.mouse('mouseMoved', x, y)
    d.mouse('mousePressed', x, y, 1)
    d.mouse('mouseMoved', x + gap / 2, y + 120)
    d.mouse('mouseMoved', x + gap + 2, y + 120)
    guides = d.ev("svg.querySelectorAll('[stroke-dasharray]').length")
    snapped = d.ev("nodesArray.find(n => n.id === '20').x === nodesArray.find(n => n.id === '4').x")
    d.mouse('mouseReleased', x + gap + 2, y + 120, 1)
    r.check('guide appears while snapping', guides >= 1, guides)
    r.check('node snaps into line', snapped)
    r.equal('guide clears on release', d.ev("svg.querySelectorAll('[stroke-dasharray]').length"), 0)


@section
def splitting(d, r):
    rules = Rules(SAMPLE)
    d.fresh()
    d.load(SAMPLE)
    wrong = [n for n in rules.types
             if (d.ev(f"splitBlockReason(nodesArray.find(n => n.id === {json.dumps(n)}))") is None) != rules.can_split(n)]
    r.equal('split rule matches an independent check', wrong, [])
    r.equal('expected nodes can be split', [n for n in rules.types if rules.can_split(n)], ['2', '4', '8', '11', '16', '21'])

    d.button('Split Page')
    r.check('nothing chosen: notice', 'first' in (d.notice() or ''))
    d.dismiss()
    d.click_node('13')
    d.button('Split Page')
    message = d.notice() or ''
    r.check('blocked split names the nodes', 'cross between pages' in message and '"7"' in message and '"12"' in message, message)
    d.dismiss()
    r.equal('blocked split changes nothing', d.tabs(), ['Master'])
    d.click_node('9')
    d.button('Split Page')
    r.check('leaf: notice', 'no children' in (d.notice() or ''))
    d.dismiss()
    d.click_node('root')
    d.button('Split Page')
    r.check('top node: notice', 'at the top' in (d.notice() or ''))
    d.dismiss()

    master_before = d.js("allNodes.map(n => [n.id, nodePosition(n, 'master')])")
    d.click_node('8')
    d.button('Split Page')
    r.equal('first split creates page1 and page2', d.tabs(), ['Master', 'page1', 'page2'])
    r.equal('new page opens', d.ev('pageName(currentPage)'), 'page2')
    r.equal('new page holds the node and its children', d.js('nodesArray.map(n => n.id)'), ['8', '9', '10', '14', '15'])
    r.equal('new page links back', d.js("[...document.querySelectorAll('.transfer-label')].map(t => t.textContent)"), ['Page 1'])
    d.ev('goToPage(1)')
    r.equal('page1 keeps the other 20 nodes', d.ev('nodesArray.length'), 20)
    r.equal('page1 links forward', d.js("[...document.querySelectorAll('.transfer-label')].map(t => t.textContent)"), ['Page 2'])
    node8 = "renderedElements.nodes.find(o => o.node.id === '8').el"
    r.equal('split node has a triangle', d.ev(f"{node8}.querySelectorAll('.transfer-triangle').length"), 1)
    r.equal('split node has no gate', d.ev(f"{node8}.querySelectorAll('.gate-path').length"), 0)
    r.equal('page1 starts with the Master layout', d.ev("nodesArray.filter(n => n.id !== '8').every(n => n.positions.master.x === n.x && n.positions.master.y === n.y)"), True)
    d.ev('goToPage(0)')
    r.equal('Master still has all nodes', d.ev('nodesArray.length'), 24)
    r.equal('Master has no triangles', d.ev("document.querySelectorAll('.transfer-triangle').length"), 0)
    r.equal('Master layout unchanged', d.js("allNodes.map(n => [n.id, nodePosition(n, 'master')])"), master_before)

    # Page links
    d.ev('goToPage(1)')
    point = d.js("""(() => { const b = renderedElements.nodes.find(o => o.node.id === '8').el.querySelector('.transfer-triangle').getBoundingClientRect(); return [b.x + b.width / 2, b.y + b.height * 0.7]; })()""")
    d.click_at(*point)
    r.equal('clicking a triangle follows the link', d.ev('currentPage'), 2)
    point = d.js("""(() => { const b = document.querySelector('.transfer-label').getBoundingClientRect(); return [b.x + b.width / 2, b.y + b.height / 2]; })()""")
    d.click_at(*point)
    r.equal('clicking a label follows the link', d.ev('currentPage'), 1)

    # Clicks on a page select instead of tracing
    d.click_node('22')
    r.equal('click on a page selects', d.highlighted('node-selected'), ['22'])
    r.equal('click on a page does not trace', d.highlighted('trace-node-path'), [])
    d.press_escape()
    r.equal('Esc clears the selection', d.highlighted('node-selected'), [])
    d.button('Split Page')
    r.check('page tab with nothing selected: notice', 'page1' in (d.notice() or ''))
    d.dismiss()

    # Trace stays on Master
    d.ev('goToPage(0)')
    d.click_node('23')
    red = len(d.highlighted('trace-node-path'))
    d.ev('goToPage(1)')
    r.equal('no trace on a page tab', d.highlighted('trace-node-path'), [])
    d.ev('goToPage(0)')
    r.equal('trace is still there on Master', len(d.highlighted('trace-node-path')), red)
    d.ev('setTracedNode(null)')

    # Independent layouts
    pages = "allNodes.map(n => [n.id, nodePosition(n, 'home'), nodePosition(n, 'copy')])"
    masters = "allNodes.map(n => [n.id, nodePosition(n, 'master')])"
    p = d.js(pages)
    x, y = d.node_point('1')
    d.drag(x, y, 30, 30)
    r.equal('dragging on Master leaves the pages', d.js(pages), p)
    m = d.js(masters)
    d.ev('goToPage(2)')
    x, y = d.node_point('9')
    d.drag(x, y, 30, 30)
    r.equal('dragging on a page leaves Master', d.js(masters), m)
    d.ev('goToPage(1)')
    original = d.js("(n => [n.x, n.y])(nodesArray.find(n => n.id === '8'))")
    d.ev('goToPage(2)')
    x, y = d.node_point('8')
    d.drag(x, y, 60, 40)
    d.ev('goToPage(1)')
    r.equal('moving the repeated node leaves the original', d.js("(n => [n.x, n.y])(nodesArray.find(n => n.id === '8'))"), original)

    # Already split, nested splits and page numbers
    d.ev('goToPage(0)')
    d.click_node('8')
    d.button('Split Page')
    r.check('already split: notice', 'already split' in (d.notice() or ''))
    d.dismiss()
    d.ev('goToPage(1)')
    d.click_node('11')
    d.button('Split Page')
    r.equal('splitting from a page tab', d.tabs(), ['Master', 'page1', 'page2', 'page3'])
    d.ev('goToPage(1)')
    d.click_node('2')
    d.button('Split Page')
    r.equal('splitting around existing splits', d.tabs(), ['Master', 'page1', 'page2', 'page3', 'page4'])
    d.ev('goToPage(2)')
    r.equal('back link follows a moved node', d.js("[...document.querySelectorAll('.transfer-label')].map(t => t.textContent)"), ['Page 4'])
    d.ev('goToPage(4)')
    r.check('top of a page can\'t be split', 'at the top' in (d.ev("splitBlockReason(nodesArray.find(n => n.id === '2'))") or ''))


@section
def undo_split(d, r):
    d.fresh()
    d.load(SAMPLE)
    structure = d.js('allNodes.map(n => [n.id, n.parentIds, n.page, n.splitPage])')
    master = d.js("allNodes.map(n => nodePosition(n, 'master'))")
    d.button('Undo Split')
    r.check('nothing to undo on Master: notice', 'nothing to undo' in (d.notice() or ''))
    d.dismiss()
    d.split('8')
    d.ev('goToPage(1)')
    d.split('11')
    d.ev('goToPage(1)')
    d.split('2')
    r.equal('three splits', d.tabs(), ['Master', 'page1', 'page2', 'page3', 'page4'])
    d.ev('goToPage(1)')
    d.button('Undo Split')
    r.check('nothing to undo on page1: notice', 'nothing to undo' in (d.notice() or ''))
    d.dismiss()
    d.ev('goToPage(2)')
    d.button('Undo Split')
    r.equal('page numbers close up', d.tabs(), ['Master', 'page1', 'page2', 'page3'])
    r.equal('merged into the page it came from', d.ev("nodesArray.find(n => n.id === '8').children.length"), 4)
    r.equal('links renumbered', sorted(d.js("[...document.querySelectorAll('.transfer-label')].map(t => t.textContent)")), ['Page 1', 'Page 2'])
    d.ev('goToPage(3)')
    d.button('Undo Split')
    d.ev('goToPage(2)')
    d.button('Undo Split')
    r.equal('last undo leaves only Master', d.tabs(), ['Master'])
    r.equal('Master opens', d.ev('currentPage'), 0)
    r.equal('structure restored', d.js('allNodes.map(n => [n.id, n.parentIds, n.page, n.splitPage])'), structure)
    r.equal('Master layout untouched', d.js("allNodes.map(n => nodePosition(n, 'master'))"), master)
    r.equal('CSV back to the plain format', d.ev("buildCSVText().split('\\n')[0]") + '\n', HEADER)
    d.click_node('22')
    r.equal('tracing still works', len(d.highlighted('trace-node-path')), 9)
    d.ev('setTracedNode(null)')
    d.split('8')
    r.equal('can split again', d.tabs(), ['Master', 'page1', 'page2'])


@section
def saving_and_refresh(d, r):
    d.fresh()
    d.load(SAMPLE)
    r.equal('no splits: plain CSV header', d.ev("buildCSVText().split('\\n')[0]") + '\n', HEADER)
    d.split('4', '8', '11', '16')
    d.arrange_pages()
    d.ev('goToPage(3)')
    d.click_node(d.ev('nodesArray[1].id'))
    d.ev('goToPage(0)')
    d.click_node('22')
    d.ev('goToPage(3)')
    state = """({ page: currentPage, zoom: zoomLevel, offset: canvasOffset, dark: document.body.classList.contains('dark-mode'),
        trace: tracedNode && tracedNode.id,
        nodes: allNodes.map(n => [n.id, n.page, n.splitPage, nodePosition(n, 'master'), nodePosition(n, 'home'), n.splitPage ? nodePosition(n, 'copy') : 0]) })"""
    d.ev('toggleTheme()')
    before = d.js(state)
    d.reload()
    r.equal('refresh keeps pages, layouts, zoom, theme and trace', d.js(state), before)
    d.ev('toggleTheme()')
    theme = d.js(state)
    d.reload()
    r.equal('refresh keeps a theme change', d.js(state), theme)
    x, y = d.node_point(d.ev('nodesArray[1].id'))
    d.double_click_at(x, y)
    r.check('double click works after refresh', d.modal_open())
    d.ev('closeModal()')

    saved = d.ev('buildCSVText()')
    r.check('split file has the page columns', saved.split('\n')[0].endswith(',Page,Page_X,Page_Y,Split_Page,Split_X,Split_Y'))
    d.load(saved)
    r.equal('saved file brings all pages back', d.tabs(), ['Master', 'page1', 'page2', 'page3', 'page4', 'page5'])
    r.equal('saved file opens on Master', d.ev('currentPage'), 0)
    r.equal('saving again gives an identical file', d.ev('buildCSVText()'), saved)
    d.ev('goToPage(1)')
    r.equal('links survive reloading', len(d.js("[...document.querySelectorAll('.transfer-label')].map(t => t.textContent)")), 4)

    older = ('ID,Parent_ID,Type,Title,Description,Potentiality,X,Y,Page,Split_Page,Split_X,Split_Y\n'
             'r,,OR,R,R,,10,0,1,,,\na,r,AND,A,A,,-50,170,1,2,5,5\nb,r,BASIC,B,B,,120,170,1,,,\n'
             'c,a,BASIC,C,C,,-100,180,2,,,\nd,a,BASIC,D,D,,100,180,2,,,\n')
    d.load(older)
    r.equal('older split file still opens', d.tabs(), ['Master', 'page1', 'page2'])
    r.equal('its positions go to the pages', d.js("nodePosition(allNodes[0], 'home').x"), 10)
    r.equal('its repeated node keeps its position', d.js("nodePosition(allNodes[1], 'copy')"), {'x': 5, 'y': 5})
    r.check('Master gets arranged', d.ev('nodesArray.some(n => n.x !== 0 || n.y !== 0)'))

    # Fallbacks
    d.ev("window.removeEventListener('pagehide', saveSession); sessionStorage.setItem(SESSION_KEY, '{bad json')")
    d.reload()
    r.equal('unreadable saved data: start screen', d.ev('allNodes.length'), 0)
    d.ev("window.removeEventListener('pagehide', saveSession); sessionStorage.setItem(SESSION_KEY, JSON.stringify({csv: 'ID,Parent_ID,Type\\na,nope,BASIC\\n', zoomLevel: 1, canvasOffset: {x: 0, y: 0}, isDark: false}))")
    d.reload()
    r.equal('invalid saved file: start screen', d.ev('allNodes.length'), 0)
    d.load(SAMPLE)
    other = d.browser.new_tab(d.app_url)
    time.sleep(0.5)
    r.equal('a new browser tab starts clean', other.ev('allNodes.length'), 0)
    d.browser.close_tab(other)


@section
def print_sizes(d, r):
    d.fresh()
    d.load(SAMPLE)
    r.check('unsplit file warns', d.ev("document.querySelector('.page-tab').classList.contains('page-tab-small')"))
    r.check('warning message shown', 'below 6 pt' in d.ev("document.querySelector('.page-hint').textContent"))
    r.check('tab shows its size on hover only', re.fullmatch(r'Master', d.tabs()[0]) and 'pt' in d.ev("document.querySelector('.page-tab').title"))
    d.split('4', '8', '11', '16')
    d.arrange_pages()
    rows = d.page_export_info()
    pages = [row for row in rows if row['name'] != 'Master']
    sizes = {round(row['textPt'], 2) for row in pages}
    r.equal('all pages share one text size', len(sizes), 1)
    r.check('four splits reach at least 6 pt on the sample', min(sizes) >= 6, sizes)
    for row in rows:
        r.check(f"{row['name']}: fits Letter portrait", row['widthPt'] <= 468.01 and row['heightPt'] <= 648.01, row)
        r.check(f"{row['name']}: nothing clipped", min(row['clearLeft'], row['clearTop'], row['clearRight'], row['clearBottom']) >= 0, row)
        r.check(f"{row['name']}: size matches the estimate", abs(row['textPt'] - row['size']) < 0.01, row)
    r.check('Master keeps its own size', rows[0]['textPt'] < min(sizes))
    d.ev('goToPage(1)')
    r.check('message names the page setting the size', 'set by page1' in d.ev("document.querySelector('.page-hint').textContent"))
    r.equal('no warning at 6 pt', d.ev("document.querySelectorAll('.page-tab-small').length"), 0)
    # Measured the way a viewer draws the file
    measured = d.js("""(() => {
        const out = [];
        pageNumbers().forEach(p => {
            goToPage(p);
            const host = document.createElement('div');
            host.style.cssText = 'position:absolute;visibility:hidden;width:auto;height:auto';
            host.innerHTML = getSvgData().xml;
            document.body.appendChild(host);
            out.push(+(host.querySelector('rect.node-rect').getBoundingClientRect().width * 0.75).toFixed(1));
            host.remove();
        });
        return out;
    })()""")
    r.equal('boxes draw at one physical size on every page', len(set(measured)), 1)
    # One wide page lowers them all and takes the warning
    d.ev('goToPage(3)')
    x, y = d.node_point(d.ev('nodesArray[nodesArray.length - 1].id'))
    d.drag(x, y, 700, 0, steps=10)
    small = d.js("[...document.querySelectorAll('.page-tab-small')].map(t => t.textContent)")
    r.equal('only the limiting page turns amber', small, ['page3'])
    r.check('all pages drop together', len({round(row['textPt'], 2) for row in d.page_export_info() if row['name'] != 'Master'}) == 1)


@section
def print_sizes_tall_and_wide(d, r):
    # The two ways a diagram can be limited: a tall chain by height, a long file name by width.
    chain = HEADER + 'n0,,OR,T,D,,,\n' + ''.join(f'n{i},n{i - 1},OR,T{i},D,,,\n' for i in range(1, 30)) + 'leaf,n29,BASIC,L,L,,,\n'
    d.fresh()
    d.load(chain)
    row = d.page_export_info()[0]
    r.check('tall diagram: fits the page height, label included', row['heightPt'] <= 648.01, row)
    r.check('tall diagram: fills the page height', row['heightPt'] > 640, row)
    d.load(HEADER + 'a,,BASIC,A,A,,,\n')
    d.ev("sourceFileName = '" + 'x' * 400 + ".csv'; renderAll()")
    row = d.page_export_info()[0]
    r.check('very long label: fits the page width', row['widthPt'] <= 468.01, row)


@section
def exports(d, r):
    def clear_downloads():
        for name in os.listdir(d.downloads):
            os.remove(os.path.join(d.downloads, name))

    def wait_for(count):
        for _ in range(60):
            names = [n for n in os.listdir(d.downloads) if not n.endswith('.crdownload')]
            if len(names) >= count:
                return sorted(names)
            time.sleep(0.1)
        return sorted(os.listdir(d.downloads))

    d.fresh()
    clear_downloads()
    d.button('Export SVG')
    time.sleep(0.5)
    r.equal('nothing loaded: no files', os.listdir(d.downloads), [])
    d.load(SAMPLE)
    d.button('Export SVG')
    r.equal('no splits: one file', wait_for(1), ['threat_tree.svg'])
    clear_downloads()
    d.split('4', '8', '11', '16')
    d.arrange_pages()
    d.ev('goToPage(0)')
    d.click_node('22')
    before = d.js("[zoomLevel, canvasOffset, allNodes.map(n => [n.x, n.y]), currentPage, tracedNode.id]")
    d.button('Export SVG')
    expected = ['threat_tree_master.svg'] + [f'threat_tree_page{i}.svg' for i in range(1, 6)]
    r.equal('Master and every page download', wait_for(6), expected)
    r.equal('your view stays as it was', d.js("[zoomLevel, canvasOffset, allNodes.map(n => [n.x, n.y]), currentPage, tracedNode.id]"), before)
    for name in expected:
        with open(os.path.join(d.downloads, name), encoding='utf-8') as f:
            xml = f.read()
        r.check(f'{name}: self-contained', 'var(--' not in xml and 'pt"' in xml)
        r.check(f'{name}: no trace', not re.search(r'trace-|#dc2626|#ea580c', xml))
        r.check(f'{name}: no duplicate colours', not re.search(r'#fde68a|#bfdbfe|#bbf7d0', xml))
        r.check(f'{name}: dark lines', '#111827' in xml and '#9ca3af' not in xml)
    with open(os.path.join(d.downloads, 'threat_tree_page1.svg'), encoding='utf-8') as f:
        r.check('page links kept', '>Page 2<' in f.read())
    with open(os.path.join(d.downloads, 'threat_tree_master.svg'), encoding='utf-8') as f:
        xml = f.read()
        r.check('Master file is complete', xml.count('interactive-node') == 24 and 'transfer-triangle' not in xml)
    clear_downloads()
    d.ev('goToPage(3)')
    d.button('Export SVG')
    r.equal('same files from any tab', wait_for(6), expected)
    r.equal('stays on the same tab', d.ev('currentPage'), 3)
    # Opened as images, the way another program would see them, boxes are one size on every page
    drawn = []
    for name in expected[1:]:
        with open(os.path.join(d.downloads, name), encoding='utf-8') as f:
            xml = f.read()
        r.check(f'{name}: carries no page styling', not re.match(r'<svg[^>]*\b(class|id)=', xml))
        size = d.ev("""new Promise(res => {
            const image = new Image();
            image.onload = () => res(image.naturalWidth);
            image.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(%s)));
        })""" % json.dumps(xml))
        units = float(re.search(r'viewBox="0 0 ([\d.]+)', xml).group(1))
        drawn.append(round(size / units, 2))
    r.equal('pictures all draw at one scale', len(set(drawn)), 1)
    clear_downloads()
    d.ev('toggleTheme()')
    d.button('Export SVG')
    time.sleep(0.5)
    r.check('dark mode: explained', 'Dark Mode' in (d.notice() or ''))
    r.equal('dark mode: no files', os.listdir(d.downloads), [])
    d.dismiss()
    d.ev('toggleTheme()')
    name, width = d.ev("""new Promise(res => {
        HTMLAnchorElement.prototype.click = function () {
            const image = new Image();
            image.onload = () => res([this.download, image.naturalWidth]);
            image.src = this.href;
        };
        exportPNG();
    })""")
    r.equal('PNG exports only this tab', name, 'threat_tree_page3.png')
    r.check('PNG is high resolution', width > 1000, width)


@section
def export_labels(d, r):
    import datetime
    today = datetime.date.today().isoformat()
    label = lambda: re.search(r'class="export-label"[^>]*>([^<]*)<', d.ev('getSvgData().xml')).group(1)
    d.fresh()
    d.ev(f"new Promise(res => {{ processFile(new File([{json.dumps(SAMPLE)}], 'my threat tree.csv')); setTimeout(res, 200); }})")
    d.dismiss()
    r.equal('no splits: file and date', label(), f'my threat tree.csv · {today}')
    d.split('4', '8', '11', '16')
    d.arrange_pages()
    r.equal('Master is named', label(), f'Master diagram · my threat tree.csv · {today}')
    d.ev('goToPage(2)')
    r.equal('page and page count', label(), f'Page 2 of 5 · my threat tree.csv · {today}')
    r.equal('nothing extra on screen', d.ev("svg.querySelectorAll('.export-label').length"), 0)
    r.equal('leaves the on-screen diagram alone', d.ev("document.querySelectorAll('.export-label').length"), 0)
    d.reload()
    r.equal('file name survives a refresh', label(), f'Page 2 of 5 · my threat tree.csv · {today}')
    d.ev('undoSplit()')
    d.ev('goToPage(2)')
    r.equal('page count follows Undo Split', label(), f'Page 2 of 4 · my threat tree.csv · {today}')
    # Every tab: label sits inside the picture, below the drawing
    for page in d.js('allTabs()'):
        d.ev(f'goToPage({page})')
        info = d.js("""(() => {
            const host = document.createElement('div');
            host.style.cssText = 'position:absolute;visibility:hidden;width:auto;height:auto';
            host.innerHTML = getSvgData().xml;
            document.body.appendChild(host);
            const s = host.querySelector('svg').getBoundingClientRect();
            const t = host.querySelector('.export-label').getBoundingClientRect();
            const lowest = Math.max(...[...host.querySelectorAll('g.interactive-node')].map(g => g.getBoundingClientRect().bottom));
            const out = { inside: t.left >= s.left && t.right <= s.right && t.top >= s.top && t.bottom <= s.bottom, below: t.top >= lowest - 1 };
            host.remove();
            return out;
        })()""")
        r.check(f'tab {page}: label inside the picture and below the drawing', info['inside'] and info['below'], info)
    # A name wider than a small page widens that picture rather than being cut off
    d.ev("sourceFileName = 'a_very_long_source_file_name_for_a_small_diagram_with_many_characters_in_it_v12.csv'")
    d.load(HEADER + 'a,,BASIC,A,A,,,\n')
    d.ev("sourceFileName = 'a_very_long_source_file_name_for_a_small_diagram_with_many_characters_in_it_v12.csv'")
    wide = d.js("""(() => {
        const host = document.createElement('div');
        host.style.cssText = 'position:absolute;visibility:hidden;width:auto;height:auto';
        host.innerHTML = getSvgData().xml;
        document.body.appendChild(host);
        const s = host.querySelector('svg').getBoundingClientRect(), t = host.querySelector('.export-label').getBoundingClientRect();
        host.remove();
        return t.right <= s.right;
    })()""")
    r.check('long file name still fits', wide)
    # Names are text, never markup
    d.ev("sourceFileName = 'a<b>&.csv'")
    xml = d.ev('getSvgData().xml')
    r.check('special characters stay valid', 'parsererror' not in d.js("new DOMParser().parseFromString(%s, 'image/svg+xml').documentElement.outerHTML" % json.dumps(xml)))


@section
def named_font(d, r):
    d.fresh()
    d.load(SAMPLE)
    xml = d.ev('getSvgData().xml')
    fonts = set(re.findall(r'font-family="([^"]+)"', xml))
    r.equal('exports name the font', fonts, {'Arial, Helvetica, sans-serif'})
    on_screen = d.js("[...new Set([...svg.querySelectorAll('text')].map(t => t.getAttribute('font-family')))]")
    r.equal('the screen uses the same font', on_screen, ['Arial, Helvetica, sans-serif'])
    r.check('text is measured in that font', 'Arial' in d.ev('TEXT_FONT') and 'Arial' in d.ev('POTENTIALITY_FONT'))
    d.ev("nodesArray.length")
    href = d.ev("""new Promise(res => {
        HTMLAnchorElement.prototype.click = function () { res(this.href); };
        exportPNG();
    })""")
    r.check('PNG still exports', href.startswith('data:image/png'))


@section
def undo_and_redo(d, r):
    state = "allNodes.map(n => [n.id, n.page, n.splitPage, nodePosition(n, 'master'), nodePosition(n, 'home'), n.splitPage ? nodePosition(n, 'copy') : 0])"
    d.fresh()
    d.load(SAMPLE)
    start = d.js(state)
    d.press_undo()
    r.equal('nothing to undo: nothing changes', d.js(state), start)
    # Drag
    x, y = d.node_point('13')
    d.drag(x, y, 90, 60)
    moved = d.js(state)
    r.check('drag changed the layout', moved != start)
    d.press_undo()
    r.equal('undo reverses a drag', d.js(state), start)
    d.press_undo(redo=True)
    r.equal('redo repeats a drag', d.js(state), moved)
    drawn = d.js("(({el, node}) => [el.getAttribute('transform'), node.x, node.y])(renderedElements.nodes.find(o => o.node.id === '13'))")
    r.check('the diagram redraws', str(drawn[1]) in drawn[0], drawn)
    d.press_undo()
    # A plain click isn't a change
    d.click_node('13')
    d.click_at(60, 900)
    r.equal('clicks add no undo steps', d.ev('undoStack.length'), 0)
    # Auto-Arrange
    d.drag(x, y, 90, 60)
    hand_placed = d.js(state)
    d.button('Auto-Arrange')
    r.check('Auto-Arrange changed the layout', d.js(state) != hand_placed)
    d.press_undo()
    r.equal('undo brings hand placement back', d.js(state), hand_placed)
    # Split and merge
    d.press_undo()
    r.equal('back to the start', d.js(state), start)
    d.click_node('8')
    d.button('Split Page')
    split_state = d.js(state)
    r.equal('split made the tabs', d.tabs(), ['Master', 'page1', 'page2'])
    d.press_undo()
    r.equal('undo reverses a split', d.tabs(), ['Master'])
    r.equal('...including the data', d.js(state), start)
    r.equal('...and returns to the tab', d.ev('currentPage'), 0)
    d.press_undo(redo=True)
    r.equal('redo repeats a split', d.js(state), split_state)
    r.equal('...and opens its page', d.ev('currentPage'), 2)
    d.ev('goToPage(1)')
    d.click_node('11')
    d.button('Split Page')
    three = d.js(state)
    d.ev('goToPage(2)')
    d.button('Undo Split')
    r.equal('Undo Split renumbers', d.tabs(), ['Master', 'page1', 'page2'])
    d.press_undo()
    r.equal('undo reverses Undo Split', d.js(state), three)
    r.equal('...with its tab back', d.tabs(), ['Master', 'page1', 'page2', 'page3'])
    d.press_undo()
    d.press_undo()
    r.equal('several undos reach the start', d.js(state), start)
    # A new change clears redo
    x, y = d.node_point('1')
    d.drag(x, y, 30, 30)
    after = d.js(state)
    d.press_undo(redo=True)
    r.equal('redo is cleared by a new change', d.js(state), after)
    # Dialogs and exports
    d.ev('openHelp()')
    d.press_undo()
    r.equal('undo does nothing while a window is open', d.js(state), after)
    d.ev('closeHelp()')
    d.ev('toggleTheme(); toggleTheme()')
    r.equal('theme is not an undo step', d.js(state), after)
    # History ends at load
    d.load(SAMPLE)
    r.equal('loading clears history', d.js('[undoStack.length, redoStack.length]'), [0, 0])
    # Limit
    d.ev("for (let i = 0; i < HISTORY_LIMIT + 20; i++) recordChange()")
    r.equal('history is capped', d.ev('undoStack.length'), 100)


@section
def unsaved_warnings(d, r):
    unsaved = lambda: d.ev('hasUnsavedChanges')
    hint = lambda: d.ev("document.querySelector('.page-hint').textContent")
    confirm_open = lambda: d.ev("!document.getElementById('confirmModal').classList.contains('hidden')")
    d.fresh()
    d.load(SAMPLE)
    r.equal('a fresh load is clean', unsaved(), False)
    r.check('no message when clean', 'Unsaved' not in hint())
    d.click_node('22')
    d.click_at(60, 900)
    d.ev('toggleTheme(); toggleTheme()')
    d.ev('fitAll()')
    r.equal('viewing changes nothing to save', unsaved(), False)
    x, y = d.node_point('13')
    d.drag(x, y, 90, 60)
    r.equal('a drag counts as unsaved', unsaved(), True)
    r.check('message shown', 'Unsaved changes' in hint(), hint())
    d.ev("HTMLAnchorElement.prototype.click = function () {}; exportCSV()")
    r.equal('Save CSV clears it', unsaved(), False)
    r.check('message clears', 'Unsaved' not in hint())
    d.reload()
    d.button('Auto-Arrange')
    r.equal('Auto-Arrange counts as unsaved', unsaved(), True)
    d.reload()
    r.equal('unsaved state survives a refresh', unsaved(), True)
    # Loading over unsaved work
    good = HEADER + 'a,,BASIC,A,A,,,\n'
    load_file = "processFile(new File([%s], 'new.csv'))" % json.dumps(good)
    d.ev(load_file)
    r.check('loading asks first', confirm_open())
    r.equal('nothing replaced yet', d.ev('allNodes.length'), 24)
    d.press_escape()
    r.check('Esc cancels', not confirm_open())
    r.equal('Esc keeps the diagram', d.ev('allNodes.length'), 24)
    r.equal('...and the unsaved state', unsaved(), True)
    d.ev(load_file)
    d.ev("document.getElementById('confirmCancel').click()")
    r.equal('Cancel keeps the diagram', d.ev('allNodes.length'), 24)
    d.ev(load_file)
    d.ev("new Promise(res => { document.getElementById('confirmYes').click(); setTimeout(res, 200); })")
    r.equal('confirming loads the file', d.ev('allNodes.length'), 1)
    r.equal('...and starts clean', unsaved(), False)
    d.ev(load_file + "; new Promise(res => setTimeout(res, 200))")
    r.check('no question when there is nothing to lose', not confirm_open())
    # The browser's warning before leaving
    d.load(SAMPLE)
    x, y = d.node_point('13')
    d.drag(x, y, 30, 30)
    d.tab.dialogs.clear()
    d.tab.call('Page.reload')
    time.sleep(0.5)
    d.ev('1')
    r.equal('leaving with unsaved work warns', d.tab.dialogs, ['beforeunload'])
    r.equal('...and the diagram survives', d.ev('allNodes.length'), 24)
    d.ev("HTMLAnchorElement.prototype.click = function () {}; exportCSV()")
    d.click_node('13')
    d.tab.dialogs.clear()
    d.tab.call('Page.reload')
    time.sleep(0.5)
    d.ev('1')
    r.equal('leaving after saving does not warn', d.tab.dialogs, [])


@section
def help_panel(d, r):
    d.fresh()
    d.button('Help')
    r.check('opens before a file is loaded', d.help_open())
    box = d.js("""(b => ({ scroll: b.scrollHeight, client: b.clientHeight, sideways: b.scrollWidth > b.clientWidth }))(document.getElementById('helpBody'))""")
    r.check('long text scrolls', box['scroll'] > box['client'], box)
    r.check('no sideways scrolling', not box['sideways'], box)
    d.press_escape()
    r.check('Esc closes', not d.help_open())
    d.load(SAMPLE)
    d.click_node('22')
    zoom = d.ev('zoomLevel')
    d.button('Help')
    d.tab.call('Input.dispatchMouseEvent', type='mouseWheel', x=750, y=450, deltaX=0, deltaY=600)
    time.sleep(0.2)
    r.check('scrolling moves the help text', d.ev("document.getElementById('helpBody').scrollTop") > 0)
    r.equal('scrolling does not zoom the diagram', d.ev('zoomLevel'), zoom)
    d.press_escape()
    r.equal('Esc in Help keeps the trace', d.ev('tracedNode.id'), '22')
    d.button('Help')
    r.equal('reopens at the top', d.ev("document.getElementById('helpBody').scrollTop"), 0)
    d.click_at(20, 500)
    r.check('clicking outside closes', not d.help_open())
    r.equal('clicking outside keeps the trace', d.ev('tracedNode.id'), '22')
    d.button('Help')
    d.ev("[...document.querySelectorAll('#helpModal button')].pop().click()")
    r.check('Close button closes', not d.help_open())
    text = d.ev("document.getElementById('helpBody').textContent")
    for topic in ('Split Page', 'Undo Split', 'Export SVG', 'Export PNG', 'Save CSV', 'Auto-Arrange', 'Master', 'Parent_ID', 'Ctrl+Z', 'Unsaved changes'):
        r.check(f'mentions {topic}', topic in text)
    r.equal('Help never reaches exports', len(re.findall('help', d.ev('getSvgData().xml'), re.I)), 0)


@section
def window_sizes(d, r):
    d.fresh()
    d.load(SAMPLE)
    measure = """(() => {
        const bar = document.querySelector('.action-bar').getBoundingClientRect();
        const tabs = document.querySelector('.page-tab').getBoundingClientRect();
        const boxes = renderedElements.nodes.map(o => o.el.getBoundingClientRect());
        const buttons = [...document.querySelectorAll('.action-bar button')].map(b => b.getBoundingClientRect());
        return {
            belowBar: Math.min(...boxes.map(b => b.top)) >= bar.bottom,
            aboveTabs: Math.max(...boxes.map(b => b.bottom)) <= tabs.top,
            onScreen: Math.min(...boxes.map(b => b.left)) >= 0 && Math.max(...boxes.map(b => b.right)) <= innerWidth,
            buttonsOnScreen: buttons.every(b => b.left >= 0 && b.right <= innerWidth)
        };
    })()"""
    try:
        for width, height in ((1500, 1000), (1280, 800), (1100, 800), (900, 700)):
            d.tab.call('Emulation.setDeviceMetricsOverride', width=width, height=height, deviceScaleFactor=1, mobile=False)
            time.sleep(0.15)
            d.ev('fitAll()')
            result = d.js(measure)
            r.check(f'{width}x{height}: Fit All clears the toolbar, tabs and edges and every button is on screen', all(result.values()), result)
    finally:
        d.tab.call('Emulation.clearDeviceMetricsOverride')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--app', default=DEFAULT_APP, help='HTML file to test')
    parser.add_argument('--only', default='', help='run only sections whose name contains this')
    args = parser.parse_args()
    app = os.path.abspath(args.app)
    if not os.path.exists(app):
        sys.exit(f'Not found: {app}')

    download_dir = tempfile.mkdtemp(prefix='threat_tree_downloads_')
    browser = Browser(download_dir)
    results = Results()
    started = time.time()
    try:
        driver = Driver(browser.tab, 'file://' + app, results, download_dir)
        driver.browser = browser
        for function in SECTIONS:
            if args.only not in function.__name__:
                continue
            results.section = function.__name__
            section_start = time.time()
            print(f'{function.__name__} ...', flush=True)
            try:
                function(driver, results)
            except Exception as error:  # A crash fails this section but lets the rest run
                results.failures.append(f'{function.__name__}: stopped early: {error}')
                print(f'  FAIL stopped early: {error}')
            print(f'  {time.time() - section_start:.0f} s', flush=True)
    finally:
        browser.close()
        shutil.rmtree(download_dir, ignore_errors=True)

    print(f'\n{results.passed} checks passed, {len(results.failures)} failed, in {time.time() - started:.0f} seconds.')
    for failure in results.failures:
        print(f'  FAILED {failure}')
    sys.exit(1 if results.failures else 0)


if __name__ == '__main__':
    main()
