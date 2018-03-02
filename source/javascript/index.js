
$(".remove_from_dir").on("click", (e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var toshi_id = $(self).data('toshi-id');
    if (toshi_id) {
        $("#remove_from_dir_form_" + toshi_id).submit();
    } else {
        $("#remove_from_dir_form").submit();
    }
});

$(".remove_featured").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var toshi_id = $(self).data('toshi-id');
    if (toshi_id) {
        $("#remove_featured_form_" + toshi_id).submit();
    } else {
        $("#remove_featured_form").submit();
    }
});

$(".set_featured").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var toshi_id = $(self).data('toshi-id');
    console.log(toshi_id);
    if (toshi_id) {
        $("#set_featured_form_" + toshi_id).submit();
    } else {
        $("#set_featured_form").submit();
    }
});

$(".remove_blocked").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var toshi_id = $(self).data('toshi-id');
    if (toshi_id) {
        $("#remove_blocked_form_" + toshi_id).submit();
    } else {
        $("#remove_blocked_form").submit();
    }
});

$(".set_blocked").click((e) => {
    e.preventDefault();
    var self = e.currentTarget;
    var toshi_id = $(self).data('toshi-id');
    console.log(toshi_id);
    if (toshi_id) {
        $("#set_blocked_form_" + toshi_id).submit();
    } else {
        $("#set_blocked_form").submit();
    }
});

$(".logout").click((e) => {
  e.preventDefault();
  $("#logout_form").submit();
});

$("button.add_category").click((e) => {
  e.preventDefault();
  $("#add_category_form").submit();
});

$("div.edit_category").dblclick((e) => {
  e.preventDefault();
  var self = e.currentTarget;
  var name = $(self).text();
  var inp = $('<input type="text" name="category" placeholder="Category..." value="' + name + '">')
  $(self).parent().append(inp);
  $(self).parent().append('<input type="submit" value="update">');
  $(self).detach();
  inp.focus();
  inp.select();
});

//edit dapp 
$('tr.dapp').one('input change', function() {
    var tr = $(this),
        td = $('<td></td>'),
        saveChangesButton = $('<button class="js-update" type="submit">Save Changes</button>'),
        button = tr.find('.js-update');

   if(button.length){
       return;
   } 

    td.append(saveChangesButton);    
    tr.append(td);

    saveChangesButton.click(function(){
        saveChangesButton.attr('disabled', true);
    
        var avatar = tr.find('.js-avatar')[0].files[0],
            name = tr.find('.js-name').text(),
            dappUrl = tr.find('.js-dapp-url').text(),
            desc = tr.find('.js-desc').text(),
            entityUrl = tr.data('entity-url'),
            formData = new FormData();
    
        formData.append('avatar', avatar);
        formData.append('name', name);
        formData.append('url', dappUrl);
        formData.append('description', desc);
    
        $.ajax({
            type: 'POST',
            url: entityUrl,
            data: formData,
            processData: false,
            contentType:false,
        }).done(function(success){
        }).fail(function(jqXHR, textStatus, errorThrown){
            console.log(jqXHR, textStatus, errorThrown);
        }).always(function(){
            saveChangesButton.remove();
            saveChangesButton.attr('disabled', false);
        });
    });
});

//delete dapp
$('.js-delete').click(function(){
    var deleteButton = $(this),
        tr = deleteButton.closest('tr'),
        entityUrl = tr.data('entity-url');
    
    deleteButton.attr('disabled', true);

    $.ajax({
        type: 'POST',
        url: entityUrl + '/delete'
    }).done(function(success){
        tr.remove();
    }).fail(function(){
        deleteButton.attr('disabled', false);
    })
});

//preview the avatar
function readURL(input) {
    if (input.files && input.files[0]) {
        var avatar = $(input).parent().find('img'),
            reader = new FileReader();

        reader.onload = function(e) {
            avatar.attr('src', e.target.result);
        }

        reader.readAsDataURL(input.files[0]);
    }
}

//when new avatar uploaded, show new avatar
$(".js-avatar").change(function() {
    readURL(this);
});