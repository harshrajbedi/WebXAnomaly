from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from django.shortcuts import render, redirect
from .forms import PcapFileForm
import subprocess

def home(request):
    return render(request, 'app.html')

def upload_pcap(request):
    if request.method == 'POST':
        form = PcapFileForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()  # Save the file to the model
            return redirect('success')  # Redirect to a success page
    else:
        form = PcapFileForm()
    return render(request, 'upload.html', {'form': form})

def analysis(request):
    result = subprocess.run(['python3', 'analysis.py'], capture_output=True, text=True)
    output = result.stdout
    errors = result.stderr
    return render(request, 'analysis.html', {
        'output': output,
        'errors': errors,
    })