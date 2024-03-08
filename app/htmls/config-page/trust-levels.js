//import {showPopup } from "./misc";


/**
 * Event to tell main script to reload trust preferences (neccessary when
 * deleting trust level)
 */
const eventTrustLevelDeleted = new Event("deletedTrustLevel")


/**
 * Lädt die Trust Levels Tabelle
 */
export function loadTrustLevelSettings(json_config, f_showPopup) {

    let table_rows = "";
    let trust_levels = Object.entries(json_config['trust-levels']);
    trust_levels.sort((a, b) => a[1] - b[1]);
    //console.log(trust_levels);
    trust_levels.forEach(entry => {
        const [key, value] = entry;
        //console.log(key + " is " + value);

        let rank_input = `<input type="number" min=1 max=100 value=${value} class="trust-level-rank-input"/>`
        let del_btn = `<td class="btn trust-level-delete" style="text-align: center;">x</td>`;
        let add_info = ``;

        if (key === "Untrusted" || key === "Standard Trust") {
            del_btn = `<td></td>`;
        }
        if (key === "Untrusted") {
            rank_input = ``;
            add_info = `
                <span class="info-icon" info-id="trust-level-untrusted">
                    &#9432;
                </span>`;
        }
        if (key === "Standard Trust") {
            add_info = `
            <span class="info-icon" info-id="trust-level-standard">
                &#9432;
            </span>`;
        }

        let table_row = `
            <tr>
                <td>${key}${add_info}</td>
                <td>${rank_input}</td>
                ${del_btn}
            </tr>`
        table_rows += table_row;
    });
    let table_body = document.getElementById('trust-levels-table-body');
    table_body.innerHTML = table_rows += `
        <tr>
            <td colspan="1">
                <input type="text" placeholder="___" class="trust-level-add"/>
            </td>
            <td colspan="2" class="btn trust-level-add" 
                style=" font-weight: bolder; color: whitesmoke; height:30px; 
                        background-color:#3D7F6E; font-size: larger;">
                +
            </td>
        </tr>`;

    loadTrustLevelSettingsEventListeners(json_config, f_showPopup);
}


function loadTrustLevelSettingsEventListeners(json_config, f_showPopup) {
    // OnChange rank inputs
    let rank_inputs = document.querySelectorAll('input.trust-level-rank-input');
    rank_inputs.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.addEventListener("change", (e) => {
                let level_name = e.target.closest('tr').children[0].innerHTML.trim();
                let level_rank = e.target.value;
                if (level_rank != "") {
                    level_rank = parseInt(level_rank);
                    // No ranks above 100
                    if (level_rank > 100) {
                        level_rank = 100;
                        e.target.value = 100;
                    }
                    console.log("changing to " + level_rank);
                    json_config['trust-levels'][level_name] = level_rank;
                    
                } else {
                    console.log("rank nicht gültig")
                }
                //json_config['trust-levels'][level_name] = level_rank;
                // TODO: check that it is a number, sonst rot umranden?
                // TODO: oder already taken --> obwohl ist egal
            });
        }
    });

    // Delete Trust Level
    let del_btns = document.querySelectorAll('td.trust-level-delete');
    del_btns.forEach(elem => {
        if (!elem.hasAttribute('listener')) {
            elem.setAttribute("listener", "true");
            elem.addEventListener("click", (e) => {
                let level_name = e.target.closest('tr').children[0].innerHTML.trim();

                if (checkIfTrustlevelIsUsed(json_config, level_name) === true) {
                    f_showPopup("This trust level is in use by at least one of your configured preferences. You cannot delete this level.", ['Got it.']);
                } else {
                    delete json_config['trust-levels'][level_name];
                    loadTrustLevelSettings(json_config);
                    // Reload trust preference settings, because they may not be
                    // able to use the trust level anymore (still shows in old
                    // dropdowns)
                    document.dispatchEvent(eventTrustLevelDeleted)
                }
            });
        }
    });

    // Add trust level
    let add_btn = document.querySelector('td.trust-level-add');
    if (!add_btn.hasAttribute('listener')) {
        add_btn.setAttribute("listener", "true");
        add_btn.addEventListener("click", () => {
            let new_level_name = document.querySelector('input.trust-level-add').value.trim();

            json_config['trust-levels'][new_level_name] = 100;
            
            loadTrustLevelSettings(json_config);
        });
    }
}


/**
 * Check if any preference uses the specified trust level
 */
function checkIfTrustlevelIsUsed(json_config, level) {
    let result = false;
    try {
        Object.entries(json_config['legacy-trust-preference']).forEach(elem => {
            const [_, preferences] = elem;
            preferences.forEach((trustlevel, _) => {
                if (trustlevel == level) {
                    console.log(trustlevel + " is " + level);
                    result = true;
                } else {
                    console.log(trustlevel + " is not " + level);
                }
            });
        });
    
        return result;
    } catch (e) {
        console.log(e);
    } 
}