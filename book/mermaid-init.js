// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

(() => {
    // Convert ```mermaid code blocks to <pre class="mermaid"> elements
    const codeBlocks = document.querySelectorAll('code.language-mermaid');
    codeBlocks.forEach((block) => {
        const pre = block.parentElement;
        const div = document.createElement('pre');
        div.className = 'mermaid';
        div.textContent = block.textContent;
        pre.parentElement.replaceChild(div, pre);
    });

    if (codeBlocks.length === 0 && document.querySelectorAll('.mermaid').length === 0) {
        return;
    }

    const darkThemes = ['ayu', 'navy', 'coal'];
    const lightThemes = ['light', 'rust'];

    const classList = document.getElementsByTagName('html')[0].classList;

    let lastThemeWasLight = true;
    for (const cssClass of classList) {
        if (darkThemes.includes(cssClass)) {
            lastThemeWasLight = false;
            break;
        }
    }

    const theme = lastThemeWasLight ? 'default' : 'dark';
    mermaid.initialize({ startOnLoad: true, theme });

    for (const darkTheme of darkThemes) {
        const el = document.getElementById(darkTheme);
        if (el) {
            el.addEventListener('click', () => {
                if (lastThemeWasLight) {
                    window.location.reload();
                }
            });
        }
    }

    for (const lightTheme of lightThemes) {
        const el = document.getElementById(lightTheme);
        if (el) {
            el.addEventListener('click', () => {
                if (!lastThemeWasLight) {
                    window.location.reload();
                }
            });
        }
    }
})();
