$(document).ready(function () {
    $("#uploadForm").submit(function (event) {
        console.log('test');
        submitForm();
        return false;
    });
});

function submitForm() {
	var form_data = new FormData();
	form_data.append('file', $('#file').prop('files')[0]);
	form_data.append('keywords', $('#KeywordsTextArea').val());
	console.log(form_data);

	console.log('tsttest');
    $.ajax({
        type: "POST",
        url: "/upload",
		contentType: false,
        cache: false,
        processData: false,
		data: form_data,
        success: function (response) {
        	console.log('success!');
            $("#uploadFileButton").html(response);
            $("#UploadFileModal").modal('hide');
        },
        error: function () {
            alert("Error");
        }
    });
}
