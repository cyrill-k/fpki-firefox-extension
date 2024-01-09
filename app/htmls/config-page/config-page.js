import * as trust_preferences from "./trust-preferences.js"
import * as ca_sets from "./ca-sets.js"
import * as trust_levels from "./trust-levels.js"
import * as misc from "./misc.js"
import { clone } from "../../js_lib/helper.js";
import { toOldConfig, toNewConfig, convertJSONConfigToMap} from "../../js_lib/config.js";


/*
    This script holds a working copy of the original live config object.
    Whenever the changes are saved, the original is replaced by this copy.
*/ 
let json_config = {};

var port = browser.runtime.connect({
    name: "config to background communication"
});

let set_builder; // global ca set builder class instance


document.addEventListener('DOMContentLoaded', async () => {
    try {
        /* DEV
        document.getElementById('printConfig').addEventListener('click', async () => {
            await requestConfig();
            printConfig();
        });
        */
        document.getElementById('downloadConfig').addEventListener('click', function() {
            port.postMessage("downloadConfig");
        });
        document.getElementById('resetConfig').addEventListener('click', async () => {
            await resetConfig();
            reloadSettings();
        });
        
        document.getElementById('uploadConfig').addEventListener('click', async () => {
            let file = document.getElementById("file").files[0];
            let reader = new FileReader();
            
            reader.onload = async function(e){
                //port.postMessage({type: "uploadConfig", value: e.target.result});
                const response = await browser.runtime.sendMessage({type: "uploadConfig", value: convertJSONConfigToMap(e.target.result)});
                //setConfig(response.config);
                console.log("RESONSE:");
                console.log(response.config);
                // Update json config without changing the reference
                const new_json_config = toNewConfig(response.config); 
                Object.entries(new_json_config).forEach(entry => {
                    const [key, new_value] = entry
                    json_config[key] = new_value
                })
                console.log(json_config);
                location.reload(true);
            }
            reader.readAsText(file);
        });
        
        document.querySelectorAll('button.save-changes').forEach( (elem) => {
            elem.addEventListener('click', async (e) => {
                saveChanges(e)
                console.log("Configuration changes have been saved");
            });
        });
        document.querySelectorAll('button.reset-changes').forEach(elem => {
            elem.addEventListener("click", async (e) => {
                await resetChanges(e);
            })
        });
        document.getElementById('advancedButton').addEventListener("click", (e) => {
            let adv_settings = document.getElementById('advanced-settings');
            if (adv_settings.hidden) {
                e.target.innerHTML = "Hide";
                adv_settings.hidden = false;
            } else {
                e.target.innerHTML = "Show";
                adv_settings.hidden = true;
            }
        });
        document
            .querySelectorAll("span.info-icon-old")
            .forEach(elem => {
                elem.addEventListener("click", (e) => {
                    let box = e.target.parentElement.children[2];
                    misc.toggleElement(box);
                });
            });

        
        document
            .querySelectorAll(`i.info-icon-old`)
            .forEach(elem => {
                if (!elem.hasAttribute('listener')) {
                    elem.setAttribute('listener', "true")
                    elem.addEventListener("click", () => {
                        const info_box = document.querySelector(
                            `div.info-box-old[data-info-id="${elem.getAttribute('data-info-id')}"]`
                        )
                        misc.toggleElement(info_box)
                    })
                }
            })

        document.addEventListener('deletedTrustLevel', () => {
            console.log("Trust-Level deleted. Reloading Trust Preferences..")
            trust_preferences.updateTrustPreferences(json_config)
        })
            
        // Initialize config
        await initConfig();
        // Initially load settings
        await reloadSettings();
    } catch (e) {
        console.log("config button setup: " + e);
    }
});


/**
 * Prints live config object to html as JSON string
 * 
 * Currently unused. Normal users dont need this
 */
async function printConfig() {
    var configCodeElement = document.getElementById("config-code");
    configCodeElement.innerHTML = "config = " + JSON.stringify(json_config, undefined, 4);
    reloadSettings();
}


/**
 * Ask background script to reset config to default.
 * Background script in turn will respond with the reset config.
 */
async function resetConfig() {
    const answer = await misc.showPopup(
        "Do you really want to reset all settings?",
        ["No", "Yes"]
    );
    if (answer == "Yes") {
        const response = await browser.runtime.sendMessage("resetConfig");
        const new_json_config = toNewConfig(response.config);
        Object.entries(new_json_config).forEach(entry => {
            const [key, new_value] = entry
            json_config[key] = new_value
        })
        console.log("CONFIG RESET.");
    }
}


/**
 * Request live config from background script to initialize config
 */
async function initConfig() {
    const response = await browser.runtime.sendMessage("requestConfig");
    json_config = toNewConfig(response.config);
}


/**
 * Post configuration changes to live config in background script
 */
async function postConfig() {
   port.postMessage({ "type": "postConfig", "value": toOldConfig(json_config) });
}


/**
 * Load configuration from live json config object and set html elements accordingly
 */
export async function reloadSettings() {
    // Load legacy trust preferences
    //trust_preferences.loadUserPolicies(json_config);
    trust_preferences.initTrustPreferences(json_config);
    // Load CA Sets
    ca_sets.initCASets(json_config);
    // Load CA Sets
    loadCASets(json_config);
    loadCASetBuilder(json_config);
    // Load trust levels settings
    trust_levels.loadTrustLevelSettings(json_config, misc.showPopup);
    // Load mapserver settings
    loadMapserverSettings();
    // Load other settings
    document.querySelector("input.cache-timeout").value = json_config['cache-timeout'];
    document.querySelector("input.max-connection-setup-time").value = json_config['max-connection-setup-time'];
    document.querySelector("input.proof-fetch-timeout").value = json_config['proof-fetch-timeout'];
    document.querySelector("input.proof-fetch-max-tries").value = json_config['proof-fetch-max-tries'];
    document.querySelector("input.mapserver-quorum").value = json_config['mapserver-quorum'];
    document.querySelector("input.mapserver-instances-queried").value = json_config['mapserver-instances-queried'];
    document.querySelector("input.send-log-entries-via-event").value = json_config['send-log-entries-via-event'];
    document.querySelector("input.wasm-certificate-parsing").value = json_config['wasm-certificate-parsing'];

    document.querySelector('input.cache-timeout').addEventListener("input", () => {
        json_config['cache-timeout'] = document.querySelector("input.cache-timeout").value;
        
    });
    document.querySelector('input.max-connection-setup-time').addEventListener("input", () => {
        json_config['max-connection-setup-time'] = document.querySelector("input.max-connection-setup-time").value;
        
    });
    document.querySelector('input.proof-fetch-timeout').addEventListener("input", () => {
        json_config['proof-fetch-timeout'] = document.querySelector("input.proof-fetch-timeout").value;
        
    });
    document.querySelector('input.proof-fetch-max-tries').addEventListener("input", () => {
        json_config['proof-fetch-max-tries'] = document.querySelector("input.proof-fetch-max-tries").value;
        
    });
    document.querySelector('input.mapserver-quorum').addEventListener("input", () => {
        json_config['mapserver-quorum'] = document.querySelector("input.mapserver-quorum").value;
        
    });
    document.querySelector('input.mapserver-instances-queried').addEventListener("input", () => {
        json_config['mapserver-instances-queried'] = document.querySelector("input.mapserver-instances-queried").value;
        
    });
    document.querySelector('input.send-log-entries-via-event').addEventListener("input", () => {
        json_config['send-log-entries-via-event'] = document.querySelector("input.send-log-entries-via-event").value;
        
    });
    document.querySelector('input.wasm-certificate-parsing').addEventListener("input", () => {
        json_config['wasm-certificate-parsing'] = document.querySelector("input.wasm-certificate-parsing").value;
        
    });


    // Event Listeners: Info-Icons
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


class CASetBuilder {
    constructor(json_config) {
        this.cas = json_config['ca-sets']['All Trust-Store CAs']['cas'];
        this.name = "Custom Set";
        this.description = "User-defined set of CAs";
        this.selected_cas = new Set();
    }

    filter(filter_str) {
        let filtered_cas = [];
        this.cas.forEach(ca => {
            if (ca.toLowerCase().includes(filter_str.toLowerCase())) {
                filtered_cas.push(ca);
            }
        });
        return filtered_cas;
    }

    /**
     * Remember if ca is checked or not (select on new filter)
     */
    toggle_select(ca) {
        if (this.selected_cas.has(ca)) {
            this.selected_cas.delete(ca);
        }
        else {
            this.selected_cas.add(ca);
        }
    }

    selected(ca) {
        if (this.selected_cas.has(ca)) {
            return true;
        } else {
            return false;
        }
    }

    add_current(json_config) {
        json_config['ca-sets'][this.name] = {
            description: this.description,
            cas: this.cas
        }

        
        reloadSettings();
    }

    test() {
        console.log("HERE COMES THE TEST");
        console.log(this.cas[0])
    }
}


/**
 * Lädt die konfigurierten CA-Sets
 */
function loadCASets(json_config) {
    // Load selectable CAs from Trust Store (-ca-set)
    let trust_store_cas = json_config['ca-sets']['All Trust-Store CAs']['cas'];
    let ca_selection = `<select name="ca_selection">`;
    trust_store_cas.forEach(ca => {
        ca_selection += `<option value="${ca}">${ca}</option>`;
    });
    ca_selection += `</select>`;

    // Event Listeners
    let open_set_btns = document.querySelectorAll('tr.ca-set-html');
    open_set_btns.forEach(btn => {
        btn.children[0].addEventListener("click", (e) => {
            let cas_row = e.target.parentElement.nextElementSibling;
            misc.toggleElement(cas_row);
            //console.log(e.target.parentElement.nextElementSibling);
            //alert("hi");
        });
    });

    let delete_set_buttons = document.querySelectorAll('tr.ca-set-html');
    delete_set_buttons.forEach(btn => {
        if (btn.children[0].innerHTML !== "All Trust-Store CAs") {
            btn.children[2].addEventListener("click", (e) => {
                let set_name = btn.children[0].innerHTML;
                //console.log("HOHO: ");
                //console.log(json_config['ca-sets']['All Trust-Store CAs'])
                delete json_config['ca-sets'][set_name];
                //console.log("HOHO: ");
                //console.log(json_config['ca-sets']['All Trust-Store CAs'])
                
                reloadSettings();
            });
        } 
    });
}


/**
 * 
 */
function loadCASetBuilder(json_config) {
    set_builder = new CASetBuilder(json_config);

    // CA Checkboxes
    let ca_div = document.querySelector('div#ca-sets-builder-cas');
    //let filter_str = e.target.previousElementSibling.value;

    let ca_checkboxes = ``;
    let all_cas = set_builder.cas;
    all_cas.forEach(ca => {
        ca_checkboxes += `
            <input type="checkbox" id="${ca}" class="ca-set-builder-checkbox"/>
            <label for="${ca}">${ca}</label><br>`;
    });
    ca_div.innerHTML = ca_checkboxes;

    // Event Listeners
    setupCASetBuilderEventListeners(json_config);
}


/**
 * 
 */
function setupCASetBuilderEventListeners(json_config) {

    // CA Filter (OnChange)
    let filter_input = document.querySelector("input.filter-cas");
    //console.log(filter_input);
    if (! filter_input.hasAttribute('listener')) {
        filter_input.addEventListener("input", (e) => {
            let ca_div = document.querySelector('div#ca-sets-builder-cas');
            let filter_str = e.target.value;
    
            let ca_checkboxes = ``;
            let filtered_cas = set_builder.filter(filter_str);
            filtered_cas.forEach(ca => {
                let checked = (set_builder.selected(ca)) ? "checked" : "";
                ca_checkboxes += `
                    <input type="checkbox" id="${ca}" class="ca-set-builder-checkbox" ${checked}/>
                    <label for="${ca}">${ca}</label><br>`;
            });
            // console.log(filtered_cas);
            ca_div.innerHTML = ca_checkboxes;
            e.target.setAttribute("listener", "true");
            setupCASetBuilderEventListeners();
        });
    }
    
    // CA Selection
    let checkboxes = document.querySelectorAll('.ca-set-builder-checkbox');
    checkboxes.forEach(box => {
        box.addEventListener("change", (e) => {
            set_builder.toggle_select(e.target.nextElementSibling.innerHTML);
        });
    });

    // Add CA Set
    let add_btn = document.querySelector('button#add-ca-set');
    if (!add_btn.hasAttribute("listener")) {
        add_btn.setAttribute("listener", "true");
        add_btn.addEventListener("click", async (e) => {
            // Dont allow empty set name
            let set_name = document.querySelector('input#ca-sets-builder-name').value.trim();
            if (set_name == "") {
                await misc.showPopup("Please enter a set name.", ["Ok."])
                const y = document
                    .querySelector('input#ca-sets-builder-name')
                    .getBoundingClientRect().top + window.pageYOffset - 25;

                window.scrollTo({top: y, behavior: 'smooth'});
                return
            }
            let set_description = document.querySelector('input#ca-sets-builder-description').value.trim();
            let set_cas = [];
            set_builder.selected_cas.forEach(ca => {
                set_cas.push(ca);
            });
            // Add custom cas from textfield
            let custom_cas = document.querySelector('textarea#ca-sets-builder-custom-cas').value.split('\n');
            custom_cas = custom_cas.filter(ca => ca !== "");
            custom_cas.forEach(ca => {
                set_cas.push(ca.trim());
            });
    
            json_config['ca-sets'][set_name] = {
                description: set_description,
                cas: set_cas
            }
            document.querySelector('input#ca-sets-builder-name').value = "";
            document.querySelector('input#ca-sets-builder-description').value = "";
            document.querySelector('textarea#ca-sets-builder-custom-cas').value = "";
            document.querySelector('#ca-sets-settings-section').scrollIntoView();
            
            reloadSettings();
        });
    }
}


/**
 * Mapserver Settings
 */
function loadMapserverSettings() {
    // Load mapservers into table
    var mapserver_rows = "";
    json_config.mapservers.forEach(mapserver => {
        mapserver_rows +=  "<tr>" + 
                                "<td>" + mapserver.identity + "</td>" +
                                "<td>" + mapserver.domain + "</td>" +
                                "<td>" + mapserver.querytype + "</td>" +
                                "<td> <button class='delete btn_mapserver_delete'>Delete</button> </td>" +
                            "</tr>";
    });
    mapserver_rows +=   "<tr id='row_mapserver_add'>" + 
                            "<td><input id='input_mapserver_add_identity' type='text' placeholder='Identity' /></td>" +
                            "<td><input id='input_mapserver_add_domain' type='text' placeholder='Domain' /></td>" +
                            "<td><input type='text' placeholder='lfpki-http-get' disabled='disabled' /></td>" +
                            "<td> <button id='btn_mapserver_add'>Add Mapserver</button> </td>" +
                        "</tr>";
    document.getElementById('mapservers-table-body').innerHTML = mapserver_rows;
    // Add event listener to buttons to delete mapservers
    Array.from(document.getElementsByClassName('btn_mapserver_delete')).forEach(elem => {
        elem.addEventListener("click", function() {
            // TODO: assumes no duplicate mapserver identities
            let identity = this.parentElement.parentElement.cells[0].innerHTML;
            let filtered = json_config.mapservers.filter(item => item.identity !== identity);
            json_config.mapservers = filtered;
            
            reloadSettings();
            return;
        });
    });
    // Add event listener to button for adding a mapserver
    document.getElementById('btn_mapserver_add').addEventListener("click", () => {
        json_config.mapservers.push({
            "identity": document.getElementById('input_mapserver_add_identity').value,
            "domain": document.getElementById('input_mapserver_add_domain').value,
            "querytype": "lfpki-http-get"
        })
        
        reloadSettings();
        return;
    });
}


/**
 * Reset changes that have been made on the configuration page without saving.
 * Resets only changes made to the section of the pressed reset button.
 */
async function resetChanges(e) {
    // Get affirmation from user
    const answer = await misc.showPopup(
        "Reset changes?",
        ["No", "Yes!"]
    );
    if (answer == "No") {
        return;
    }

    const live_config = toNewConfig((await browser.runtime.sendMessage("requestConfig")).config);

    // Mapservers
    if (e.target.classList.contains('mapservers')) {
        json_config['mapservers'] = live_config['mapservers'];
        //

        reloadSettings();
    }
    // Legacy Trust Preferences
    if (e.target.classList.contains('legacy-trust-preference')) {
        json_config['legacy-trust-preference'] = live_config['legacy-trust-preference'];
        //
        trust_preferences.updateTrustPreferences(json_config);
        //reloadSettings();
    }
    // Policy Trust Preferences
    if (e.target.classList.contains('policy-trust-preference')) {
        json_config['policy-trust-preference'] = live_config['policy-trust-preference'];
        //

        reloadSettings();
    }
    // CA Sets
    if (e.target.classList.contains('ca-sets')) {
        json_config['ca-sets'] = live_config['ca-sets'];
        //

        reloadSettings();
    }
    // Other Settings
    if (e.target.classList.contains('other-settings')) {
        json_config['cache-timeout'] = live_config['cache-timeout'];
        json_config['max-connection-setup-time'] = live_config['max-connection-setup-time'];
        json_config['proof-fetch-timeout'] = live_config['proof-fetch-timeout'];
        json_config['proof-fetch-max-tries'] = live_config['proof-fetch-max-tries'];
        json_config['mapserver-quorum'] = live_config['mapserver-quorum'];
        json_config['mapserver-instances-queried'] = live_config['mapserver-instances-queried'];
        json_config['send-log-entries-via-event'] = live_config['send-log-entries-via-event'];
        json_config['wasm-certificate-parsing'] = live_config['wasm-certificate-parsing'];
        //
        reloadSettings();
    }

    if (e.target.classList.contains('trust-levels')) {
        json_config['trust-levels'] = live_config['trust-levels'];
        //
        reloadSettings();
    }
}


/**
 * Save changes that have been made to the settings in the section of the 
 * pressed button.
 * 
 */
function saveChanges(e) {

    if (e.target.classList.contains('mapservers')) {
        postConfig();
    }

    if (e.target.classList.contains('legacy-trust-preference')) {
        postConfig();
    }

    if (e.target.classList.contains('ca-sets')) {
        postConfig();
    }

    if (e.target.classList.contains('other-settings')) {
        // loadCurrentInputToLocalConfig();
        postConfig();
    }

    if (e.target.classList.contains('trust-levels')) {
        postConfig();
    }

    //reloadSettings();
    misc.showPopup(
        "Changes have been saved!",
        ["Nice."]
    );
}