import { showPopup, toggleElement } from "./misc.js";
import { delCASetPreferences } from "./trust-preferences.js";


/**
 * Loads all CA Sets into the correct DOM-container.  
 * Should only be used on full reload.
 */
export function initCASets(json_config) {
    const main_div = document.querySelector('div#ca-sets-casets');
    main_div.innerHTML = "";

    Object.entries(json_config['ca-sets']).forEach(elem => {
        const [caset_name, _] = elem;
        
        buildCASetDiv(caset_name);

        loadCASetContent(json_config, caset_name);
    });

    //sortDomains();

    //loadEventListeners(json_config);
}


/**
 * Only updated the casets. Doesnt reset expanded status of divs.  
 */
export function updateCASets(json_config) {

    Object.entries(json_config['ca-sets']).forEach(elem => {
        const [caset_name, _] = elem;

        if (document.querySelector(
            `div.ca-sets-caset[data-caset="${caset_name}"]`
        )) {
            // load caset into existing divs (prevent collapse of divs)
            loadCASetContent(json_config, caset_name);
        } else {
            //console.log("Creating new div for caset " + caset_name);
            buildCASetDiv(caset_name);
            loadCASetContent(json_config, caset_name);
        }
    });

    //sortDomains();
}


/**
 * Create div for casets and add to ca-sets div
 */
function buildCASetDiv(caset_name) {
    const main_div = document.querySelector('div#ca-sets-casets');
    // load caset template
    const caset_div = document.importNode(
        document.getElementById("ca-sets-caset-template").content, 
        true
    );
    // init caset header
    caset_div
        .querySelector('select.ca-sets-caset-header')
        .appendChild((() => {
            const el = document.createElement('option');
            el.textContent = caset_name;
            return el;
        })());
    // init all childrens `data-caset`
    caset_div
        .querySelectorAll('[data-caset]')
        .forEach (elem => {
            elem.setAttribute('data-caset', caset_name);
        });
    // hide delete button, if "all trust-store-cas"
    if (caset_name === "All Trust-Store CAs") {
        caset_div.querySelector(`div.ca-sets-caset-more`).remove()
    }
    // load domain div into DOM
    main_div.appendChild(caset_div);
}


/**
 * (Re)loads the casets content-div
 */
function loadCASetContent(json_config, caset_name) {
    // get the casets div
    const caset_div = document
        .querySelector(`div.ca-sets-caset-content[data-caset="${caset_name}"]`);
    const name_div = caset_div.querySelector(
        'div.ca-sets-caset-name'
    );
    const description = caset_div.querySelector(
        'p.ca-sets-caset-description'
    );
    // reset
    name_div.innerHTML = "";
    description.innerHTML = "";
    // TODO: will this be needed?
    try {
        // on first load there is no such div, ignore error
        caset_div.querySelector(
            'div.add-trust-preference-row'
        ).remove();
    } catch (e) {}

    // Load CA Set Name
    //name_div.innerHTML = caset_name;
    // Load CA Set Descripton
    if (json_config['ca-sets'][caset_name]['description'] !== "") {
        description.textContent = json_config['ca-sets'][caset_name]['description']
    } else {
        description.textContent = "No description available."
    }
    
    // Load CAs
    loadCASetCAs(json_config, caset_name)

    loadEventListeners(json_config);
}


/**
 * Load CAs included in the CA Set
 * 
 * TODO: make editable
 */
function loadCASetCAs(json_config, caset_name) {
    const cas_div = document.querySelector(
        `div.ca-sets-caset-cas-content[data-caset="${caset_name}"]`
    )
    cas_div.innerHTML = ""

    let cas_list = document.createElement("ul");
   
    json_config['ca-sets'][caset_name]['cas'].forEach(ca => {
        let list_entry = document.createElement("li")
        list_entry.textContent = ca
        cas_list.appendChild(list_entry)
    });
    // TEST
    //let test = document.createElement("p");
    //test.textContent = String(json_config['ca-sets'][caset_name]['cas'])

    if (cas_list.childElementCount > 0) {
        cas_div.appendChild(cas_list);
    } else {
        const no_cas_msg = document.createElement("p");
        no_cas_msg.textContent = "No CAs in this set."
        no_cas_msg.style.margin = "0"
        cas_div.appendChild(no_cas_msg);
    }
    
}


/**
 * 
 */
function loadEventListeners(json_config) {
    /*
        Expand CA Set
    */
    const caset_selects = document
        .querySelectorAll('select.ca-sets-caset-header');
    // remove default event expand
    caset_selects.forEach(elem => {
        elem.addEventListener("mousedown", (e) => {
            e.preventDefault();
        });
    });
    // custom expand
    caset_selects.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', "true");
            elem.addEventListener("click", () => {
                toggleElement(document.querySelector(
                    `div.ca-sets-caset-content[data-caset="${elem.getAttribute('data-caset')}"`
                ));
            });
        }
    });
    
    /*
        Expand CA Set
    */
    const cas_selects = document
        .querySelectorAll('select.ca-sets-caset-cas-header');
    // remove default event expand
    cas_selects.forEach(elem => {
        elem.addEventListener("mousedown", (e) => {
            e.preventDefault();
        });
    });
    // custom expand
    cas_selects.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', "true");
            elem.addEventListener("click", () => {
                toggleElement(document.querySelector(
                    `div.ca-sets-caset-cas-content[data-caset="${elem.getAttribute('data-caset')}"`
                ));
            });
        }
    });

    /*
        Delete CA Set
    */
    const caset_delete_buttons = document.querySelectorAll(
        `button.ca-sets-caset-delete`
    )
    caset_delete_buttons.forEach(btn => {
        if (!btn.hasAttribute('listener')) {
            btn.setAttribute('listener', "true")
            btn.addEventListener("click", async () => {
                if (isUsedByPreference(json_config, btn.getAttribute('data-caset'))) {
                    const answer = await showPopup(
                        "CA Set is used in Trust Preferences. Delete corresponding preferences?", 
                        ["No.", "Yes."]
                    )
                    if (answer == "Yes.") {
                        delCASetPreferences(json_config, btn.getAttribute('data-caset'))
                        delCASet(json_config, btn.getAttribute('data-caset'))
                    }
                } else {
                    delCASet(json_config, btn.getAttribute('data-caset'))
                }
            });
        }
    })
}


/**
 * Checks if the caset is used in any preferences currently.
 */
function isUsedByPreference(json_config, caset_name) {
    let is_used = false

    Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
        const [_, prefs] = elem;
        prefs.forEach((_, pref_caset) => {
            console.log("compargin '" + caset_name + "' and '" + pref_caset + "'")
            if (pref_caset === caset_name) {
                is_used = true;
            }
        })
    })

    return is_used;
}


/**
 * Delete CA Set and reload the UI
 */
function delCASet(json_config, caset_name) {
    delete json_config['ca-sets'][caset_name]
    document.querySelector(
        `div.ca-sets-caset[data-caset="${caset_name}"]`
    ).remove();
    updateCASets(json_config)
}