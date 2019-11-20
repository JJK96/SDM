$(document).ready(function () {
    $("#uploadForm").submit(function () {
        submitUploadForm();
        return false;
    });
});

$(document).ready(function () {
    $("#searchForm").submit(function () {
        retrieveSearchResults();
        return false;
    });
});

function submitUploadForm() {
    let form_data = new FormData();
    form_data.append('file', $('#file').prop('files')[0]);
	form_data.append('keywords', $('#KeywordsTextArea').val());
	form_data.append('clientID', $('#uploadClientID option:selected').text());

    $.ajax({
        type: "POST",
        url: "/upload",
		contentType: false,
        cache: false,
        processData: false,
		data: form_data,
        success: function (response) {
            $('<div class="alert alert-success radius-bordered fade show" id="uploadAlert" role="alert">\n' +
                '    Upload of file successful!\n' +
                '</div>\n').appendTo('body').delay(3000).fadeOut(function () {
                $(this).remove()
            });
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
        clientID: $("#clientID option:selected").text(),
    };

    $.ajax({
        type: "GET",
        url: "/search",
        data: data,
        success: function (response) {
            $("#searchResults").html(response)
        },
        error: function (error) {
            alert(error.message)
        }
    })
}
