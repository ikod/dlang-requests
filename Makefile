librequests.a: source/requests/http.d
	dub build -b release --force

clean:
	dub clean
	rm -f librequests.a
