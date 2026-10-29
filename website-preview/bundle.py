from pathlib import Path
p=Path(__file__).parent
html=(p/'index.html').read_text();css=(p/'styles.css').read_text();js=(p/'app.js').read_text()
assert html.count('<link rel="stylesheet" href="styles.css">')==1
assert html.count('<script src="app.js" defer></script>')==1
assert '</script>' not in js
html=html.replace('<link rel="stylesheet" href="styles.css">','<style>\n'+css+'\n</style>')
html=html.replace('<script src="app.js" defer></script>','<script>\n'+js+'\n</script>')
(p/'TrendyJoes_Approved_Interactive_Preview.html').write_text(html)
print('Bundled new standalone HTML bytes',len(html))
