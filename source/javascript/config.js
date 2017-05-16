$(".remove_admin").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var token_id = $(self).data('token-id');
    if (token_id) {
        $("#remove_admin_form_" + token_id).submit();
    }
});
