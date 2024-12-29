let input;
let form;

function setup() {
	input = document.getElementById("body");
	body.value = convertToMarkdown(body.value)

	input.addEventListener("input", eventCallback);
	setVal(input);

	form = document.getElementById("edit-form")
	form.onsubmit = async (e) => {
		e.preventDefault();
		const form = e.currentTarget;
		const url = form.action;

		try {
		  const formData = new FormData(form);
		  console.log(formData)
		  const response = await fetch(url, {
			  method: 'POST',
			  body: formData
		  });
		  console.log(response);
		  if (response.redirected) {
			  window.location.href = response.url;
		  }
		} catch (error) {
		  console.error(error);
		}
	}
}

function eventCallback(event) {
	setVal(event.target);
}

function setVal(elem) {
	document.getElementById("rendered-showdown-output").innerHTML =
		convertToHTML(elem.value);
}

function convertToHTML(md) {
	const converter = new showdown.Converter();
	converter.simpleLineBreaks = true;
	return converter.makeHtml(md);
}

function convertToMarkdown(html) {
	const converter = new showdown.Converter();
	converter.simpleLineBreaks = true;
	return converter.makeMarkdown(html);
}