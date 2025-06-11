## 1 `xml.etree.ElementTree` used unsafely

**Issue** Standard library parser expands entities by default.

### 1A `ElementTree.parse()`

```regex
xml\.etree\.ElementTree\.parse\(
```

### 1B `ElementTree.fromstring()`

```regex
xml\.etree\.ElementTree\.fromstring\(
```

### 1C Alias `ET.parse()`

```regex
ET\.parse\(
```

### 1D Alias `ET.fromstring()`

```regex
ET\.fromstring\(
```

**Example**

```python
import xml.etree.ElementTree as ET
tree = ET.parse(upload.path)            # untrusted XML
```

**Security Impact** Attacker-controlled DTD defs fetch remote files or exfiltrate data.

---

## 2 `xml.dom.minidom` raw parsing

**Issue** `minidom` leaves entity expansion on.

### 2A `minidom.parse()`

```regex
xml\.dom\.minidom\.parse\(
```

### 2B `minidom.parseString()`

```regex
xml\.dom\.minidom\.parseString\(
```

---

## 3 `lxml.etree` with unsafe defaults or flags

**Issue** `lxml` is safe **only** when you disable DTD, no-network, entities.

### 3A `lxml.etree.parse()`

```regex
lxml\.etree\.parse\(
```

### 3B `lxml.etree.fromstring()`

```regex
lxml\.etree\.fromstring\(
```

### 3C Parser crafted with `resolve_entities=True`

```regex
etree\.XMLParser\(.*resolve_entities\s*=\s*True
```

### 3D Parser crafted with `load_dtd=True`

```regex
etree\.XMLParser\(.*load_dtd\s*=\s*True
```

### 3E Parser crafted with `no_network=False`

```regex
etree\.XMLParser\(.*no_network\s*=\s*False
```

---

## 4 `xml.sax` parsers allowing external entities

**Issue** Default SAX parser fetches external general/parameter entities.

### 4A `xml.sax.make_parser()`

```regex
xml\.sax\.make_parser\(
```

### 4B `xml.sax.parse()`

```regex
xml\.sax\.parse\(
```

### 4C `xml.sax.parseString()`

```regex
xml\.sax\.parseString\(
```

### 4D Explicitly enabling external general entities

```regex
setFeature\(\s*xml\.sax\.handler\.feature_external_ges\s*,\s*True
```

### 4E Explicitly enabling external parameter entities

```regex
setFeature\(\s*xml\.sax\.handler\.feature_external_pes\s*,\s*True
```

---

## 5 `xmltodict` convenience wrapper

**Issue** `xmltodict.parse()` just delegates to unsafe `expat/ElementTree`.

### 5A Basic call

```regex
xmltodict\.parse\(
```

### 5B Parsing directly from `open()`

```regex
xmltodict\.parse\(\s*open\(
```

---

## 6 `xml.pulldom` streaming parse

**Issue** Pull-DOM sits atop unsafe expat.

### 6A `pulldom.parse()`

```regex
xml\.pulldom\.parse\(
```

### 6B `pulldom.parseString()`

```regex
xml\.pulldom\.parseString\(
```

---

## 7 Low-level expat builders

**Issue** Expat expands entities unless you disable them.

### 7A `expatbuilder.parse()`

```regex
expatbuilder\.parse\(
```

### 7B `xml.parsers.expat.parse()`

```regex
xml\.parsers\.expat\.parse\(
```

---

## 8 `libxml2` C-bindings

**Issue** `libxml2` requires explicit entity hardening.

### 8A `libxml2.parseDoc()`

```regex
libxml2\.parseDoc\(
```

### 8B `libxml2.parseFile()`

```regex
libxml2\.parseFile\(
```

### 8C `libxml2.readFile()`

```regex
libxml2\.readFile\(
```

---

## 9 `lxml.objectify` shortcuts

**Issue** Objectify wraps `lxml.etree` with same hazards.

### 9A `objectify.parse()`

```regex
objectify\.parse\(
```

### 9B `objectify.fromstring()`

```regex
objectify\.fromstring\(
```

---

## 10 BeautifulSoup used with XML parsers

**Issue** `BeautifulSoup(..., "xml")` cascades into unsafe libraries.

### 10A `BeautifulSoup(..., "xml")`

```regex
BeautifulSoup\([^,]+,\s*["']xml["']
```

### 10B `BeautifulSoup(..., "lxml-xml")`

```regex
BeautifulSoup\([^,]+,\s*["']lxml-xml["']
```

---

## 11 Expat parser factory

**Issue** Direct expat instantiation keeps entities on.

### 11A `ParserCreate()`

```regex
xml\.parsers\.expat\.ParserCreate\(
```

---

## 12 Hidden file-open → `parse`

**Issue** Developers sometimes pipe `open()` straight into an unsafe XML loader.

### 12A `lxml.etree.parse(open(...))`

```regex
etree\.parse\(\s*open\(
```

### 12B `ET.parse(open(...))`

```regex
ET\.parse\(\s*open\(
```