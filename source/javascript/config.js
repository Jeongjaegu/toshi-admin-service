$(".remove_admin").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var toshi_id = $(self).data('toshi-id');
    if (toshi_id) {
        $("#remove_admin_form_" + toshi_id).submit();
    }
});
