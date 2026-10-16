document.addEventListener("DOMContentLoaded", () => {
    fetch('/encryption').then(resp => resp.json()).then(data => updatePanel('encryption', data));
    fetch('/threat_detection').then(resp => resp.json()).then(data => updatePanel('threat_detection', data));
    fetch('/response').then(resp => resp.json()).then(data => updatePanel('response', data));
    fetch('/compliance').then(resp => resp.json()).then(data => updatePanel('compliance', data));
    fetch('/integration').then(resp => resp.json()).then(data => updatePanel('integration', data));
    fetch('/update_manager').then(resp => resp.json()).then(data => updatePanel('update_manager', data));
});

function updatePanel(id, data) {
    const panel = document.getElementById(id);
    for (const [key, value] of Object.entries(data)) {
        const elem = panel.querySelector(`#${key}`);
        if (elem) elem.textContent = value;
    }
}