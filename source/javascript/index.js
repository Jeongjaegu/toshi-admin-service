
$(".remove_from_dir").on("click", (e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var token_id = $(self).data('token-id');
    if (token_id) {
        $("#remove_from_dir_form_" + token_id).submit();
    } else {
        $("#remove_from_dir_form").submit();
    }
});

$(".remove_featured").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var token_id = $(self).data('token-id');
    if (token_id) {
        $("#remove_featured_form_" + token_id).submit();
    } else {
        $("#remove_featured_form").submit();
    }
});

$(".set_featured").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var token_id = $(self).data('token-id');
    console.log(token_id);
    if (token_id) {
        $("#set_featured_form_" + token_id).submit();
    } else {
        $("#set_featured_form").submit();
    }
});

$(".remove_blocked").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var token_id = $(self).data('token-id');
    if (token_id) {
        $("#remove_blocked_form_" + token_id).submit();
    } else {
        $("#remove_blocked_form").submit();
    }
});

$(".set_blocked").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var token_id = $(self).data('token-id');
    console.log(token_id);
    if (token_id) {
        $("#set_blocked_form_" + token_id).submit();
    } else {
        $("#set_blocked_form").submit();
    }
});

$(".logout").click((e) => {
  e.preventDefault();
  $("#logout_form").submit();
});
