let body, citation, form;

function setup() {
	body = document.getElementById("body");
	body.value = convertToMarkdown(body.value);
	citation = document.getElementById("citation");
	citation.value = convertToMarkdown(citation.value);

	body.addEventListener("input", eventCallbackBody);
	citation.addEventListener("input", eventCallbackCitation);
	setVal(body, "rendered-showdown-body");
	setVal(citation, "rendered-showdown-citation");

	form = document.getElementById("edit-form");
	form.onsubmit = async (e) => {
		e.preventDefault();
		const form = e.currentTarget;
		const url = form.action;

		try {
			const formData = new FormData(form);

			const bodyHTML = convertToHTML(formData.get("body"))
			formData.set("body", bodyHTML)
			const citationHTML = convertToHTML(formData.get("citation"))
			formData.set("citation", citationHTML)

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

function eventCallbackBody(event) {
	setVal(event.target, "rendered-showdown-body");
}

function eventCallbackCitation(event) {
	setVal(event.target, "rendered-showdown-citation");
}

function setVal(elem, target) {
	document.getElementById(target).innerHTML = convertToHTML(elem.value);
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