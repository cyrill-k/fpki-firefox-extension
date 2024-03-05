import { showPopup, toggleElement } from "./misc.js";
import { getParentDomain, getWildcardDomain, isTopLevelDomain } from "../../js_lib/domain.js";


/**
 * Loads all trust preferences for all domains into the correct DOM-container.  
 * Should only be used on full reload.
 */
export function initTrustPreferences(json_config) {
    const main_div = document.querySelector('div#trust-preference-domains');
    main_div.innerHTML = "";

    Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
        const [domain_name, _] = elem;
        
        buildDomainPreferencesDiv(domain_name);
        // load domain preferences into now existing divs
        //loadDomainPreferences(json_config, domain_name);
        // load domains inherited preferences
        //loadDomainInheritedPreferences(json_config, domain_name);
        loadDomainContent(json_config, domain_name);
    });

    sortDomains();

    loadEventListeners(json_config);
}


/**
 * Create div for domain preferences and add to trust-preferences div
 */
function buildDomainPreferencesDiv(domain_name) {
    const main_div = document.querySelector('div#trust-preference-domains');
    // load domain template
    const domain_div = document.importNode(
        document.getElementById("trust-preference-domain-template").content, 
        true
    );
    // init domain header
    domain_div
        .querySelector('select.trust-preference-domain-header')
        .appendChild((() => {
            const el = document.createElement('option');
            el.textContent = domain_name;
            return el;
        })());
    // init all childrens `data-domain`
    domain_div
        .querySelectorAll('[data-domain]')
        .forEach (elem => {
            elem.setAttribute('data-domain', domain_name);
        });
    // load domain div into DOM
    main_div.appendChild(domain_div);
}


/**
 * Only updated the preferences. Doesnt reset expanded status of divs.  
 * If a domain had been deleted, full reload. will reset expanded status.
 */
export function updateTrustPreferences(json_config) {
    Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
        const [domain_name, _] = elem;

        if (document.querySelector(
            `div.trust-preference-domain[data-domain="${domain_name}"]`
        )) {
            // load domain preferences into existing divs (prevent collapse of divs)
            loadDomainContent(json_config, domain_name);
        } else {
            //console.log("Creating new div for domain " + domain_name);
            buildDomainPreferencesDiv(domain_name);
            loadDomainContent(json_config, domain_name);
        }
    });

    sortDomains();
}


/**
 * (Re)loads the domains trust preference content-div
 */
function loadDomainContent(json_config, domain_name) {
    // get the domains div
    const domain_div = document
        .querySelector(`div.trust-preference-domain-content[data-domain="${domain_name}"]`);
    const preference_div = domain_div.querySelector(
        'div.trust-preference-domain-preferences'
    );
    const inherited_preference_div = domain_div.querySelector(
        'div.trust-preference-domain-inherited-preferences'
    );
    // reset
    preference_div.innerHTML = "";
    inherited_preference_div.innerHTML = "";
    try {
        // on first load there is no such div
        domain_div.querySelector(
            'div.add-trust-preference-row'
        ).remove();
    } catch (e) {}

    loadDomainPreferences(json_config, domain_name);
    loadDomainInheritedPreferences(json_config, domain_name);

    loadEventListeners(json_config);
}


/**
 * Sort domain headers/containers  
 * TODO: nach domain-subdomain (tree-mäßig)
 */
function sortDomains() {
    let domain_divs = document.querySelectorAll(
        `div.trust-preference-domain`
    );
    // sort domains by domain-name alphabetically
    domain_divs = Array.from(domain_divs);
    domain_divs.sort((a, b) => {
        return (
            a.getAttribute('data-domain')
                .localeCompare(b.getAttribute('data-domain'))
        );
    });
    const sorted_domain_divs = document.createDocumentFragment();
    domain_divs.forEach(row => {sorted_domain_divs.appendChild(row)});
    // refill trust preferences div
    const preferences_div = document.querySelector(
        `div#trust-preference-domains`
    );
    preferences_div.innerHTML = "";
    preferences_div.appendChild(sorted_domain_divs);
}


/**
 * Loads the preferences for the given domain into the right DOM-containers
 */
function loadDomainPreferences(json_config, domain) {
    //console.log("LOADING domain preferences..")
    const preference_div = document.querySelector(
        `div.trust-preference-domain-preferences[data-domain="${domain}"]`
    );
    preference_div.innerHTML = "";
    // load preferences from config
    json_config['legacy-trust-preference'][domain].forEach(({level, "ca-set": caSet}) => {
        preference_div.appendChild(
            make_pref_row(json_config, domain, caSet, level)
        );
    });

    new Sortable(preference_div, {
        animation: 150,
        ghostClass: 'blue-background-class',
        // Changed sorting within list
        onUpdate: (/**Event*/e) => {
            updateDomainPreferenceSorting(e, json_config)
            // reload all preferences, because inherited preferences might be
            // affected
            updateTrustPreferences(json_config)
        },
    });
    /*Object
        .entries(json_config['legacy-trust-preference'][domain])
        .forEach(preference => {
            const [caset, level] = preference;
            preference_div.appendChild(
                make_pref_row(json_config, domain, caset, level)
            );
        });*/
    
    document.querySelector(
        `div.trust-preference-domain-add-preference[data-domain="${domain}"]`
    ).appendChild(
        make_pref_add_row(json_config, domain, "--select--", "--select--")
    );
}


/**
 * Update domain preference map (from json_config) to represent the same
 * ordering as manipulated via Drag and Drop on the UI.
 */
function updateDomainPreferenceSorting(/**Event*/e, json_config) {
    const prefs_entries = json_config['legacy-trust-preference'][e.target.getAttribute('data-domain')]

    let sorted_prefs_entries = []
    // extremely sophisticated algorithm right here
    if (e.oldIndex < e.newIndex) {
        for (var i = 0; i <= (e.oldIndex - 1); i++) {
            sorted_prefs_entries.push(prefs_entries[i]);
        }
        for (var i = (e.oldIndex + 1); i <= e.newIndex; i++) {
            sorted_prefs_entries.push(prefs_entries[i]);
        }
        sorted_prefs_entries.push(prefs_entries[e.oldIndex]);
        for (var i = (e.newIndex + 1); i < prefs_entries.length; i++) {
            sorted_prefs_entries.push(prefs_entries[i]);
        }
    }
    if (e.oldIndex > e.newIndex) {
        for (var i = 0; i <= (e.newIndex - 1); i++) {
            sorted_prefs_entries.push(prefs_entries[i]);
        }
        sorted_prefs_entries.push(prefs_entries[e.oldIndex]);
        for (var i = e.newIndex; i <= (e.oldIndex - 1); i++) {
            sorted_prefs_entries.push(prefs_entries[i]);
        }
        for (var i = (e.oldIndex + 1); i < prefs_entries.length; i++) {
            sorted_prefs_entries.push(prefs_entries[i]);
        }
    }
    //console.log(sorted_prefs_entries)
    // update map
    json_config['legacy-trust-preference'][e.target.getAttribute('data-domain')] = sorted_prefs_entries;
    //console.log(json_config['legacy-trust-preference'][e.target.getAttribute('data-domain')])
}


/**
 * Loads preferences, that are implicitly inherited from parent domains
 */
function loadDomainInheritedPreferences(json_config, domain) {
    const domain_prefs = json_config['legacy-trust-preference'][domain];
    let inherited_prefs = {
        // domain: Map(caset: level)
    }

    /** (local)  
     * Check if `inherited_prefs` (above) has pref for `caset` under any domain.
     * This is to check if the preference of some parent domain should be used
     * or not.
     */
    function hasInheritedPref(caset) {
        let has_pref = false;
        Object.entries(inherited_prefs).forEach(entry => {
            const [domain_name, prefs] = entry;
            prefs.forEach(({ "ca-set": caset_name }) => {
                if (caset_name == caset) {
                    has_pref = true;
                }
            });
        });
        return has_pref;
    }

    /** (local)  
     * Adds prefs that are inherited from `domain_name` if any.
     */
    function addInheritedPrefs(domain_name) {
        if (!json_config['legacy-trust-preference'].hasOwnProperty(domain_name)) {
            return;
        }

        json_config['legacy-trust-preference'][domain_name].forEach(({ "ca-set": caset, level }) => {
            // inherits, if not already defined
            if (
                (!domain_prefs.some(({ "ca-set": caSet }) => caSet === caset)) &&
                (!hasInheritedPref(caset))
            ) {
                if (!inherited_prefs.hasOwnProperty(domain_name)) {
                    inherited_prefs[domain_name] = [];
                }
                inherited_prefs[domain_name].push({ "ca-set": caset, level });
            }
        });
    }

    /** (local)  
     * Sort inherited prefs so that they are displayed in order of priority.  
     * I.e. parent domains --> child domains, and, for every domain the same
     * order that is specified in their domain preferences.  
     * 
     * `inherited_prefs` is a real Map() after this.
     */
    function sortInheritedPrefs() {
        inherited_prefs = new Map([...Object.entries(inherited_prefs)].sort((a, b) => b[0].length - a[0].length));
    }


    let parent_domain = domain;
    // if it is not a wildcard, add the corresponding wildcard domain
    if (!domain.startsWith("*.")) {
        addInheritedPrefs(getWildcardDomain(domain));
    }
    // recursively add all parent domains (including the respective wildcard certs
    while (!isTopLevelDomain(parent_domain)) {
        parent_domain = getParentDomain(parent_domain);
        addInheritedPrefs(parent_domain);
        addInheritedPrefs(getWildcardDomain(parent_domain));
    }

    // load DIV
    const inherited_prefs_div = document.querySelector(
        `div.trust-preference-domain-inherited-preferences[data-domain="${domain}"]`
    );
    // reset
    inherited_prefs_div.innerHTML = "";
    // sort inherited prefs
    sortInheritedPrefs();
    // load inherited prefs
    inherited_prefs.forEach((pref_data, domain_name) => {
        //console.log("Inherited preferences:")
        //console.log(`${domain_name}: `)
        //console.log(pref_data)
        
        // prefs
        pref_data.forEach(({level, "ca-set": caset}) => {
            //const [caset, level] = pref;

            const pref_row = document.importNode(
                document.getElementById(
                    "trust-preference-inherited-row-template"
                ).content,
                true
            );
            // caset
            const caset_option = pref_row.querySelector(
                'option.trust-preference-inherited-caset'
            );
            caset_option.textContent = caset;
            // level
            const level_option = pref_row.querySelector(
                'option.trust-preference-inherited-trustlevel'
            );
            level_option.textContent = level;
            // info box
            const info_box = pref_row.querySelector(
                `div.trust-preference-inherited-info-box`
            );
            info_box.appendChild((() => {
                const text = document.createElement('p');
                text.innerHTML = `Inherited from <b>${domain_name}</b>`;
                return text;
            })());
            // info-id attribute and info-icon
            info_box.setAttribute('info-id', `${domain}-${caset}`);
            const info_icon = pref_row.querySelector(
                `span.trust-preference-inherited-info-icon`
            );
            info_icon.setAttribute('info-id', `${domain}-${caset}`);
            // add `data-attr` to inherited pref row aswell (TESTING)
            const row_div = pref_row.querySelector('div.trust-preference-inherited-row');
            row_div.setAttribute('data-domain', domain_name);
            row_div.setAttribute('data-caset', caset);
            row_div.setAttribute('data-trustlevel', level);

            inherited_prefs_div.appendChild(pref_row);
        });
    });
    // hide if no inherited prefs
    if (inherited_prefs_div.innerHTML == "") {
        document.querySelector(
            `h4.trust-preference-domain-inherited-preferences[data-domain="${domain}"]`
        ).hidden = true;
    } else {
        document.querySelector(
            `h4.trust-preference-domain-inherited-preferences[data-domain="${domain}"]`
        ).hidden = false;
    }
}


/**
 * Builds a "row" representing the preference
 */
function make_pref_row(json_config, domain, caset, level) {
    // load preference row template
    const clone = document.importNode(
        document.getElementById("trust-preference-row-template").content, 
        true
    );

    // ca set selection
    const caset_select = clone.querySelector('select.trust-preference-caset');
    const available_casets = [caset, ...getUnconfiguredCASets(json_config, domain)];
    available_casets.forEach(set => {
        const caset_option = document.createElement('option');
        caset_option.textContent = set;
        // preselect current ca set
        if (set == caset) {
            caset_option.defaultSelected = true;
        }
        caset_select.appendChild(caset_option);
    });

    // trust level selection
    const trustlevel_select = clone.querySelector('select.trust-preference-level');
    Object.entries(json_config['trust-levels']).forEach(elem => {
        const [level_name, _] = elem;
        const level_option = document.createElement('option');
        level_option.textContent = level_name;
        // preselect current trust level
        if (level_name == level) {
            level_option.defaultSelected = true;
        }
        trustlevel_select.appendChild(level_option);
    });

    // init every element with `data-attr`
    clone.querySelectorAll(
        `[data-domain][data-caset][data-trustlevel]`
    ).forEach(elem => {
        elem.setAttribute('data-domain', domain);
        elem.setAttribute('data-caset', caset);
        elem.setAttribute('data-trustlevel', level);
    });

    return clone
}


/**
 * Builds a "row" for adding a preference
 */
function make_pref_add_row(json_config, domain) {
    // load add preference row template
    const clone = document.importNode(
        document.getElementById("add-trust-preference-row-template").content, 
        true
    );

    // ca set selection
    const caset_select = clone.querySelector('select.add-trust-preference-caset');
    caset_select.setAttribute('data-domain', domain);
    const available_casets = ["--select--", ...getUnconfiguredCASets(json_config, domain)];
    available_casets.forEach(set => {
        const caset_option = document.createElement('option');
        caset_option.textContent = set;
        // preselect current ca set
        if (set == "--select--") {
            caset_option.defaultSelected = true;
            caset_option.disabled = true;
        }
        caset_select.appendChild(caset_option);
    });

    // trust level selection
    const trustlevel_select = clone.querySelector('select.add-trust-preference-level');
    trustlevel_select.setAttribute('data-domain', domain);
    // --select-- extrawurst
    const select_option = document.createElement('option');
    select_option.textContent = "--select--";
    select_option.defaultSelected = true;
    select_option.disabled = true;
    trustlevel_select.appendChild(select_option);
    // real trust levels
    Object.entries(json_config['trust-levels']).forEach(elem => {
        const [level_name, _] = elem;
        const level_option = document.createElement('option');
        level_option.textContent = level_name;
        trustlevel_select.appendChild(level_option);
    });

    return clone
}


/**
 * 
 */
function loadEventListeners(json_config) {
    /*
        Expand domain
    */
    const domain_selects = document
        .querySelectorAll('select.trust-preference-domain-header');
    // remove default event expand
    domain_selects.forEach(elem => {
        elem.addEventListener("mousedown", (e) => {
            e.preventDefault();
        });
    });
    // custom expand
    domain_selects.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', "true");
            elem.addEventListener("click", () => {
                toggleElement(document.querySelector(
                    `div.trust-preference-domain-content[data-domain="${elem.getAttribute('data-domain')}"`
                ));
            });
        }
    });
    /*
        Delete Domain
    */
    document.querySelectorAll(
        'button.trust-preference-domain-delete'
    ).forEach(btn => {
        if (!btn.hasAttribute('listener')) {
            btn.setAttribute('listener', "true");
            btn.addEventListener('click', async () => {
                let answer = await showPopup(
                    `Delete all domain preferences for domain ${btn.getAttribute('data-domain')} ?`,
                    ["No", "Yes"]
                );
                if (answer == "Yes") {
                    delete json_config['legacy-trust-preference'][btn.getAttribute('data-domain')];
                    document.querySelector(
                        `div.trust-preference-domain[data-domain="${btn.getAttribute('data-domain')}"]`
                    ).remove();
                }

                // reload all domain contents, because inherited preferences
                // might be affected
                updateTrustPreferences(json_config);
            });
        }
    });
    /*
        Add domain
    */
    const domain_add_input = document.querySelector(
        'input.trust-preference-add-domain'
    );
    if (!domain_add_input.hasAttribute('listener')) {
        domain_add_input.setAttribute('listener', "true");
        domain_add_input.addEventListener("keydown", async (e) => {
            if (e.key == 'Enter') {
                const domain_name = domain_add_input.value;
                // no empty domain name
                if (domain_name == ""){
                    await showPopup("No empty domain allowed.", ["Ok."]);
                    return;
                }
                // no duplicate domains
                if (json_config['legacy-trust-preference'].hasOwnProperty(domain_name)) {
                    await showPopup("Domain already exists.", ["Ok."]);
                    return;
                }
                // otherwise .. add domain to config
                json_config['legacy-trust-preference'][domain_name] = [];
                updateTrustPreferences(json_config);
                domain_add_input.value = "";
            }
        });
    }
    /*
        Change trust level
    */
    const trustlevel_selects = document
        .querySelectorAll('select.trust-preference-level');
    
    trustlevel_selects.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', 'true');
            elem.addEventListener('change', () => {
                // update data-attr
                update_data_attr(
                    elem.getAttribute('data-domain'),
                    elem.getAttribute('data-caset'),
                    elem.getAttribute('data-trustlevel'),
                    null,
                    elem.value
                );
                // update json config
                const idx = json_config['legacy-trust-preference'][elem.getAttribute('data-domain')].findIndex(({"ca-set": caSet}) => caSet === elem.getAttribute('data-caset'))
                if (idx === -1) {
                    throw new Error("UI is inconsistent with internal settings")
                } else {
                    json_config['legacy-trust-preference'][elem.getAttribute('data-domain')].splice(idx, 1, {"ca-set": elem.getAttribute('data-caset'), level: elem.value})
                }
                // reload all domain contents, because inherited preferences
                // might be affected
                updateTrustPreferences(json_config);
                
                /*console.log("Changing trust level of " + 
                    elem.getAttribute('data-caset') + " to " +
                    elem.getAttribute('data-trustlevel') + " for domain " +
                    elem.getAttribute('data-domain')
                );*/
            });
        }
    });
    /*
        Change ca set
    */
    const caset_selects = document
        .querySelectorAll('select.trust-preference-caset');
    
    caset_selects.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', 'true');
            elem.addEventListener('change', (e) => {
                // backup previous caset name
                const prev_caset = elem.getAttribute('data-caset');
                // update data-attr
                update_data_attr(
                    elem.getAttribute('data-domain'),
                    elem.getAttribute('data-caset'),
                    elem.getAttribute('data-trustlevel'),
                    elem.value,
                    null
                );
                // update json config
                const idx = json_config['legacy-trust-preference'][elem.getAttribute('data-domain')].findIndex(({"ca-set": caSet}) => caSet === prev_caset)
                json_config['legacy-trust-preference'][elem.getAttribute('data-domain')].splice(idx, 1, {"ca-set": elem.getAttribute('data-caset'), "level": elem.getAttribute('data-trustlevel')})
                    // TODO: sortierung durcheinander hierdurch (später)

                // reload, because this has impilcations for the selectable 
                // options of other prefs + new pref
                //loadDomainContent(json_config, elem.getAttribute('data-domain'));
                // reload all domain contents, because inherited preferences
                // might be affected
                updateTrustPreferences(json_config);

                /*console.log("Changing trust level of " + 
                    elem.getAttribute('data-caset') + " to " +
                    elem.getAttribute('data-trustlevel') + " for domain " +
                    elem.getAttribute('data-domain')
                );*/
            });
        }
    });
    /*
        Add trust preference
    */
    const add_preference_caset_elems = document.querySelectorAll('select.add-trust-preference-caset');
    add_preference_caset_elems.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', "true");
            elem.addEventListener("change", () => {
                // if trustlevel is set aswell, add preference
                const trustlevel_select = document.querySelector(
                    `select.add-trust-preference-level[data-domain="${elem.getAttribute('data-domain')}"]`
                );
                if (trustlevel_select.value != "--select--") {
                    //alert(`adding ${elem.value} - ${trustlevel_select.value}`);
                    addPreference(
                        json_config,
                        elem.getAttribute('data-domain'),
                        elem.value,
                        trustlevel_select.value
                    );
                }
            });
        }
    });

    const add_preference_level_elems = document.querySelectorAll('select.add-trust-preference-level');
    add_preference_level_elems.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', "true");
            elem.addEventListener("change", () => {
                // if caset is set aswell, add preference
                const caset_select = document.querySelector(
                    `select.add-trust-preference-caset[data-domain="${elem.getAttribute('data-domain')}"]`
                );
                if (caset_select.value != "--select--") {
                    addPreference(
                        json_config,
                        elem.getAttribute('data-domain'),
                        caset_select.value,
                        elem.value
                    );
                }
            });
        }
    });
    /*
        Delete preference
    */
    const del_preference_elems = document.querySelectorAll(
        `div.trust-preference-delete`
    );
    del_preference_elems.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute('listener', "true");
            elem.addEventListener("click", () => {
                delPreference(
                    json_config,
                    elem.getAttribute('data-domain'),
                    elem.getAttribute('data-caset')
                );
                // reload all domain contents, because inherited preferences
                // might be affected
                updateTrustPreferences(json_config);
            });
        }
    });
    /*
        Show inherited pref info
    */
    const inherited_pref_info_icons = document.querySelectorAll(
        `span.trust-preference-inherited-info-icon`
    );
    inherited_pref_info_icons.forEach(icon => {
        if (!icon.hasAttribute('listener')) {
            icon.setAttribute('listener', "true");
            icon.addEventListener('click', (e) => {
                let info_box = document.querySelector(
                    `div.info-box[info-id="${icon.getAttribute('info-id')}"]`
                );
                //console.log(info_box);
                info_box.style.left = (e.pageX - 5) + "px";
                info_box.style.top = (e.pageY -5) + "px";
                info_box.style.display = "block";
                let screen_dim = document.querySelector('html').getBoundingClientRect();
                info_box.style['max-width'] = (screen_dim.right - e.pageX - 50) + "px";

                info_box.addEventListener("mouseleave", () => {
                    info_box.style.display = "none";
                });
            });
        }
    });
    /*
        Info-Icons
    */
    document
        .querySelectorAll("span.info-icon,i.info-icon")
        .forEach(elem => {
            if (!elem.hasAttribute('listener')) {
                elem.setAttribute('listener', "true");
                elem.addEventListener("click", (e) => {
                    let info_id = e.target.getAttribute('info-id');
                    let box = document.querySelector(`div.info-box[info-id="${info_id}"]`)
                    console.log(box)
                    box.style.left = (e.pageX - 5) + "px";
                    box.style.top = (e.pageY -5) + "px";
                    box.style.display = "block";
                    let screen_dim = document.querySelector('html').getBoundingClientRect();
                    box.style['max-width'] = (screen_dim.right - e.pageX - 50) + "px";
    
                    box.addEventListener("mouseleave", (e) => {
                        e.target.style.display = "none";
                    });
                });
            }
        });
}


/**
 * Adds specified preference (caset, level) to specified domain.
 */
function addPreference(json_config, domain, caset, level) {
    json_config['legacy-trust-preference'][domain].push({"ca-set": caset, level});
    // reload all domain contents, because inherited preferences will be
    // affected
    updateTrustPreferences(json_config)
}


/**
 * Deletes specified preference (caset) from specified domain
 */
function delPreference(json_config, domain, caSetToDelete) {
    const idx = json_config['legacy-trust-preference'][domain].findIndex(({"ca-set": caSet}) => caSet === caSetToDelete)
    json_config['legacy-trust-preference'][domain].splice(idx, 1);
    // update all prefs, as this will effect inherited prefs of other domains
    updateTrustPreferences(json_config)
}


/**
 * Synchronize data-attr. they are set at multiple elements
 */
function update_data_attr(domain, caset, level, new_caset=null, new_level=null) {
    const elements = document
        .querySelectorAll(`[data-domain="${domain}"][data-caset="${caset}"][data-trustlevel="${level}"]`);

    elements.forEach(elem => {
        //console.log("Changing element...");

        if (new_caset != null) {
            elem.setAttribute('data-caset', new_caset);
        }
        if (new_level != null) {
            elem.setAttribute('data-trustlevel', new_level);
        }
    });
}


/**
 * Returns an array of the CA Sets, that have no configured trust level yet, for
 * the given domain.
 */
function getUnconfiguredCASets(json_config, domain) {
    let configured_casets = new Set();
    json_config['legacy-trust-preference'][domain].forEach(({"ca-set": caSet}) => {
        configured_casets.add(caSet);
    });

    let all_casets = new Set();
    Object.entries(json_config['ca-sets']).forEach(set => {
        const [set_name, _] = set;
        all_casets.add(set_name);
    });

    let unconfigured_casets = [...all_casets].filter(x => !configured_casets.has(x));
    //console.log("potential casets:");
    //console.log(unconfigured_casets);

    return unconfigured_casets;
}


/**
 * Allows CA Set to be deleted. Then delete all prefereces associated to that CA
 * Set. Triggered by ca-sets.js.
 */
export function delCASetPreferences(json_config, caset_name) {
    Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
        const [domain_name, prefs] = elem;
        prefs.forEach(({"ca-set": pref_caset}) => {
            if (pref_caset == caset_name) {
                delPreference(json_config, domain_name, caset_name)
            }
        })
    })
}
