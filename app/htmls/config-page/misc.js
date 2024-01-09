/**
 * Popup to force yes-or-no decision
 * 
 * Call like this:  
 * let answer = await misc.showPopup("Möchten Sie fortfahren?");
 * 
 * TODO: allgemeiner, entscheidungsmöglichkeiten per parameter übergeben
 */
export async function showPopup(message, list_of_choices) {
    return new Promise((resolve, reject) => {
        // modal
        const modal = document.createElement('div');
        modal.className = 'modal';
        // modal content
        const modal_content = document.createElement('div');
        modal_content.classList.add('modal-content');
        // message
        const msg = document.createElement('p');
        msg.textContent = message;
        modal_content.appendChild(msg);
        // choices
        for (let choice of list_of_choices) {
            // html
            const choice_btn = document.createElement('button');
            choice_btn.textContent = choice;
            // event listener
            choice_btn.addEventListener('click', () => {
                modal.style.display = 'none';
                modal.remove();
                resolve(choice);
            });
            // add child
            modal_content.appendChild(choice_btn);
        }
        /*
        const yes_btn = document.createElement('button');
        yes_btn.textContent = "Yes";
        const no_btn = document.createElement('button');
        no_btn.textContent = "No";
        const msg = document.createElement('p');
        msg.textContent = message;
        // event listeners
        yes_btn.addEventListener('click', () => {
            modal.style.display = 'none';
            modal.remove();
            resolve("yes");
        });
        no_btn.addEventListener('click', () => {
            modal.style.display = 'none';
            modal.remove();
            resolve("no");
        });
        */

        

        modal.appendChild(modal_content);
        document.body.appendChild(modal);
    });
}


/**
 * Toggle display status of an element
 */
export function toggleElement(box) {
    if (box.hidden === true) {
        box.hidden = false;
    } else {
        box.hidden = true;
    }
}