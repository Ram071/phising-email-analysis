const fileInput = document.getElementById("email_file");
const fileName = document.getElementById("fileName");

if (fileInput) {

    fileInput.addEventListener("change", function () {

        if (this.files.length > 0) {

            fileName.textContent =
                "Selected: " + this.files[0].name;

        } else {

            fileName.textContent =
                "No file selected";

        }

    });

}


const uploadForm =
    document.getElementById("uploadForm");

if (uploadForm) {

    uploadForm.addEventListener("submit", function () {

        const button =
            uploadForm.querySelector("button");

        if (button) {

            button.textContent =
                "Analyzing...";

            button.disabled = true;

        }

    });

}
