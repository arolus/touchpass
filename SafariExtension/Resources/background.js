// Context menu for selected text: Search → engine. Needs no access to pages:
// the selection comes with the click. Google opens in a new tab, the maps in a
// small window centered over the current one.

const ROOT_ID = "search";

const ENGINES = [
    { id: "google", title: "Google", url: "https://www.google.com/search?q=" },
    { id: "google-maps", title: "Google Maps", url: "https://www.google.com/maps/search/?api=1&query=", inWindow: true },
    { id: "yandex-maps", title: "Yandex Maps", url: "https://yandex.ru/maps/?text=", inWindow: true },
];

const MAP_WINDOW = { width: 1000, height: 700 };

const api = globalThis.browser ?? globalThis.chrome;

function searchURL(engineId, text) {
    const engine = ENGINES.find((e) => e.id === engineId);
    const query = (text ?? "").trim();
    if (!engine || !query) return null;
    return engine.url + encodeURIComponent(query);
}

// Geometry that centers a window over its parent, kept inside the parent when
// the parent is smaller.
function centeredOver(parent, size) {
    const width = Math.min(size.width, parent.width);
    const height = Math.min(size.height, parent.height);
    return {
        width,
        height,
        left: Math.round(parent.left + (parent.width - width) / 2),
        top: Math.round(parent.top + (parent.height - height) / 2),
    };
}

async function openMapWindow(url, tab) {
    const parent = tab ? await api.windows.get(tab.windowId).catch(() => null) : null;
    const geometry = parent ? centeredOver(parent, MAP_WINDOW) : MAP_WINDOW;
    await api.windows.create({ url, type: "popup", ...geometry });
}

if (typeof module !== "undefined") module.exports = { ENGINES, searchURL, centeredOver };

if (api) {
    // The background page is not persistent; recreate the menu on every load so
    // a reload never leaves duplicate ids or an empty menu.
    api.contextMenus.removeAll().then(() => {
        api.contextMenus.create({
            id: ROOT_ID,
            title: "Search",
            contexts: ["selection"],
            icons: { 16: "images/search-16.png", 32: "images/search-32.png" },
        });
        for (const engine of ENGINES) {
            api.contextMenus.create({
                id: engine.id,
                parentId: ROOT_ID,
                title: engine.title,
                contexts: ["selection"],
            });
        }
    });

    api.contextMenus.onClicked.addListener((info, tab) => {
        const url = searchURL(info.menuItemId, info.selectionText);
        if (!url) return;
        if (ENGINES.find((e) => e.id === info.menuItemId).inWindow) {
            openMapWindow(url, tab);
            return;
        }
        const placement = tab ? { index: tab.index + 1, windowId: tab.windowId } : {};
        api.tabs.create({ url, ...placement });
    });
}
