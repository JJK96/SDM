$(document).ready(function () {
    $("#uploadForm").submit(function (event) {
        submitForm();
        return false;
    });
});

$(document).ready(function () {
    $("#searchForm").submit(function () {
        retrieveSearchResults();
        return false;
    });
});

function submitForm() {
	var form_data = new FormData();
	form_data.append('file', $('#file').prop('files')[0]);
	form_data.append('keywords', $('#KeywordsTextArea').val());
	console.log(form_data);

    $.ajax({
        type: "POST",
        url: "/upload",
		contentType: false,
        cache: false,
        processData: false,
		data: form_data,
        success: function (response) {
            $("#uploadFileButton").html(response);
            $("#UploadFileModal").modal('hide');
        },
        error: function () {
            alert("Error");
        }
    });
}

function retrieveSearchResults() {
    let data = {
        q: $("#query").val(),
    };

    $.ajax({
        type: "GET",
        url: "/search",
        data: data,
        success: function (response) {
            $("#searchResults").html(response)
        },
        error: function (error) {
            alert(e.message)
        }
    })
}
